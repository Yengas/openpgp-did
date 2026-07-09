use std::error::Error;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use pcsc::{Disposition, Protocols};

pub struct PcscBackend {
    card: pcsc::Card,
    mode: pcsc::ShareMode,
    reader_name: String,
}

pub struct PcscTransaction<'card> {
    transaction: pcsc::Transaction<'card>,
    was_reset: bool,
}

fn list_cards(mode: pcsc::ShareMode) -> Result<Vec<PcscBackend>, SmartcardError> {
    let context = pcsc::Context::establish(pcsc::Scope::User)
        .map_err(|err| SmartcardError::ContextError(err.to_string()))?;

    let readers = context
        .list_readers_owned()
        .map_err(|err| SmartcardError::ReaderError(err.to_string()))?;

    let mut cards = Vec::new();

    for reader in readers {
        let reader_name = reader.to_string_lossy().into_owned();

        match context.connect(&reader, mode, Protocols::ANY) {
            Ok(card) => cards.push(PcscBackend {
                card,
                mode,
                reader_name,
            }),
            Err(pcsc::Error::NoSmartcard) => {}
            Err(_) => {}
        }
    }

    Ok(cards)
}

impl PcscBackend {
    pub fn cards(mode: Option<pcsc::ShareMode>) -> Result<Vec<Self>, SmartcardError> {
        list_cards(mode.unwrap_or(pcsc::ShareMode::Shared))
    }
}

impl CardBackend for PcscBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        let ext_support = if self.reader_name.starts_with("ACS ACR122U") {
            false
        } else {
            card_caps.ext_support()
        };

        CardCaps::new(
            ext_support,
            card_caps.chaining_support(),
            card_caps.max_cmd_bytes(),
            card_caps.max_rsp_bytes(),
            card_caps.pw1_max_len(),
            card_caps.pw3_max_len(),
        )
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        Ok(Box::new(PcscTransaction::new(
            &mut self.card,
            self.mode,
            reselect_application,
        )?))
    }
}

impl<'card> PcscTransaction<'card> {
    fn new(
        card: &'card mut pcsc::Card,
        mode: pcsc::ShareMode,
        reselect_application: Option<&[u8]>,
    ) -> Result<Self, SmartcardError> {
        let mut was_reset = false;
        let mut current_card = card;

        loop {
            match current_card.transaction2() {
                Ok(transaction) => {
                    let mut pcsc_transaction = Self {
                        transaction,
                        was_reset,
                    };

                    if was_reset {
                        if let Some(application) = reselect_application {
                            let mut response = pcsc_transaction.select(application)?;

                            if response.len() > 2 {
                                response.drain(0..response.len() - 2);
                            }

                            if response != [0x90, 0x00] {
                                return Err(SmartcardError::Error(format!(
                                    "failed to reselect application: {:x?}",
                                    response
                                )));
                            }
                        }
                    }

                    return Ok(pcsc_transaction);
                }
                Err((card_after_error, pcsc::Error::ResetCard)) => {
                    was_reset = true;
                    current_card = card_after_error;

                    current_card
                        .reconnect(mode, Protocols::ANY, Disposition::ResetCard)
                        .map_err(|err| {
                            SmartcardError::Error(format!("failed to reconnect card: {err:?}"))
                        })?;
                }
                Err((_, err)) => {
                    return Err(SmartcardError::Error(format!(
                        "failed to start card transaction: {err:?}"
                    )));
                }
            }
        }
    }
}

impl CardTransaction for PcscTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        let mut response_buffer = vec![0; buf_size];
        let response = self
            .transaction
            .transmit(cmd, &mut response_buffer)
            .map_err(|err| match err {
                pcsc::Error::NotTransacted => SmartcardError::NotTransacted,
                _ => SmartcardError::Error(format!("failed to transmit APDU: {err:?}")),
            })?;

        Ok(response.to_vec())
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "reader-side PIN verification is not supported".into(),
        ))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "reader-side PIN modification is not supported".into(),
        ))
    }

    fn was_reset(&self) -> bool {
        self.was_reset
    }
}

impl From<PcscBackend> for Box<dyn CardBackend + Sync + Send> {
    fn from(backend: PcscBackend) -> Self {
        Box::new(backend)
    }
}

pub fn exactly_one_card() -> Result<PcscBackend, Box<dyn Error>> {
    let mut backends = PcscBackend::cards(None)?;

    if backends.len() == 1 {
        return Ok(backends.remove(0));
    }

    let readers = backends
        .iter()
        .map(|backend| backend.reader_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let detail = if readers.is_empty() {
        String::new()
    } else {
        format!(" ({readers})")
    };

    Err(format!(
        "expected exactly one backend to be listed but got = {}{}",
        backends.len(),
        detail
    )
    .into())
}
