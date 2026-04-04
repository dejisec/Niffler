use std::any::Any;

use tokio::task::JoinError;

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("pipeline config error: {0}")]
    Config(String),

    #[error("pipeline channel closed unexpectedly")]
    ChannelClosed,

    #[error("pipeline phase panicked: {0}")]
    PhasePanicked(String),

    #[error("pipeline phase failed: {0}")]
    PhaseFailed(String),
}

impl From<JoinError> for PipelineError {
    fn from(err: JoinError) -> Self {
        if err.is_panic() {
            let panic_payload = err.into_panic();
            let msg = extract_panic_message(&panic_payload);
            Self::PhasePanicked(msg)
        } else {
            Self::PhaseFailed(err.to_string())
        }
    }
}

impl From<String> for PipelineError {
    fn from(msg: String) -> Self {
        Self::PhaseFailed(msg)
    }
}

fn extract_panic_message(payload: &Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipeline_error_from_join_error() {
        let handle = tokio::task::spawn(async {
            panic!("test panic");
        });
        let join_err = handle.await.unwrap_err();
        let pipeline_err = PipelineError::from(join_err);
        assert!(
            matches!(pipeline_err, PipelineError::PhasePanicked(_)),
            "expected PhasePanicked, got: {pipeline_err:?}"
        );
    }
}
