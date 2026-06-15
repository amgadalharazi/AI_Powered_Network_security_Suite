// ort 2.0.0-rc.12 notes:
//   - Session is at ort::session::Session
//   - Tensor::from_array accepts (shape, vec) tuple — avoids ndarray version mismatch
//     because the project's ndarray and ort's ndarray may differ in semver
//   - inputs! returns Vec, not Result — no ? on the macro call itself
//   - try_extract_tensor::<f32>() returns (&Shape, &[f32]) — index the slice with .1[i]
use ort::session::Session;
use ort::value::Tensor;
use serde_json::Value;
use std::fs;

pub struct AIDetector {
    session: Session,
    mean: Vec<f32>,
    scale: Vec<f32>,
    threshold: f32,
}

impl AIDetector {
    pub fn new(
        model_path: &str,
        scaler_path: &str,
        threshold: f32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // No Environment in ort 2.x — build the session directly.
        let session = Session::builder()?.commit_from_file(model_path)?;

        let scaler_json = fs::read_to_string(scaler_path)?;
        let v: Value = serde_json::from_str(&scaler_json)?;
        let mean: Vec<f32> = serde_json::from_value(v["mean"].clone())?;
        let scale: Vec<f32> = serde_json::from_value(v["scale"].clone())?;

        Ok(Self {
            session,
            mean,
            scale,
            threshold,
        })
    }

    pub fn predict(&mut self, features: &[f32]) -> Result<(bool, f32), Box<dyn std::error::Error>> {
        if features.len() != self.mean.len() {
            return Err(format!(
                "Feature count mismatch: expected {}, got {}",
                self.mean.len(),
                features.len()
            )
            .into());
        }

        // Standard-scale; guard against zero scale
        let scaled: Vec<f32> = features
            .iter()
            .zip(&self.mean)
            .zip(&self.scale)
            .map(|((&x, &m), &s)| if s != 0.0 { (x - m) / s } else { 0.0 })
            .collect();

        let n = scaled.len();

        // Pass a (shape, vec) tuple — OwnedTensorArrayData is implemented for this
        // regardless of which ndarray version the project uses.
        let input_tensor = Tensor::<f32>::from_array(([1, n], scaled))?;

        // inputs! returns Vec in rc.12, not a Result — no ? here
        let inputs = ort::inputs!["float_input" => input_tensor];
        let outputs = self.session.run(inputs)?;

        // try_extract_tensor returns (&Shape, &[T]) in rc.12 — use .1 for the slice
        let (_shape, data) = outputs[0].try_extract_tensor::<f32>()?;
        // data is flat row-major: [p_benign, p_attack] for batch size 1
        let attack_prob = data[1];
        Ok((attack_prob > self.threshold, attack_prob))
    }
}
