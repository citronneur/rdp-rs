use rand::Rng;

/// Generate a vector sized size fill with random value
///
/// # Example
/// ```
/// use rdp::model::rnd::random;
/// let vector = random(128);
/// assert_eq!(vector.len(), 128);
/// ```
pub fn random(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}
