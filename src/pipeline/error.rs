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

    #[test]
    fn pipeline_error_config_display() {
        let err = PipelineError::Config("bad rules path".into());
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("config"), "expected 'config' in: {msg}");
    }

    #[test]
    fn pipeline_error_channel_closed_display() {
        let err = PipelineError::ChannelClosed;
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("channel"), "expected 'channel' in: {msg}");
    }

    #[test]
    fn pipeline_error_phase_panicked_display() {
        let err = PipelineError::PhasePanicked("discovery".into());
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("panic") || msg.contains("discovery"),
            "expected 'panic' or 'discovery' in: {msg}"
        );
    }

    #[test]
    fn pipeline_error_phase_failed_display() {
        let err = PipelineError::PhaseFailed("walker error".into());
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("walker") || msg.contains("failed"),
            "expected 'walker' or 'failed' in: {msg}"
        );
    }

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

    #[test]
    fn pipeline_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PipelineError>();
    }
}
