//! The tray icon: the Kenter logo with a coloured dot carrying the node's
//! health. The logo is pre-rendered from its SVG skin
//! (`examples/render_icons.rs`), so the tray needs no image libraries.

use crate::status::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Online, on the roster, fee balance fine.
    Green,
    /// Working, but needs attention or is mid-transition: low fees,
    /// relay unreachable, awaiting funds, joining, unbonding, no backup.
    Amber,
    /// Paused by the operator.
    Grey,
    /// Cannot run without the operator.
    Red,
}

impl Health {
    pub fn of(state: State, paused: bool, low_funds: bool, backed_up: bool) -> Self {
        if paused {
            return Health::Grey;
        }
        match state {
            State::Failed => Health::Red,
            State::Online if !low_funds && backed_up => Health::Green,
            State::Stopped => Health::Grey,
            _ => Health::Amber,
        }
    }

    fn rgb(self) -> [u8; 3] {
        match self {
            Health::Green => [46, 160, 67],
            Health::Amber => [219, 140, 0],
            Health::Grey => [130, 130, 130],
            Health::Red => [200, 40, 40],
        }
    }

    /// The tray image: the Kenter logo with a status dot in its lower
    /// right corner, anti-aliased, with a dark rim so it reads on light
    /// and dark taskbars alike.
    pub fn rgba(self) -> Vec<u8> {
        let [r, g, b] = self.rgb();
        let mut px = LOGO.to_vec();
        let (cx, cy) = (SIZE as f32 - 7.5, SIZE as f32 - 7.5);
        let outer = 7.0;
        let rim = outer - 1.5;
        for y in 0..SIZE {
            for x in 0..SIZE {
                let d = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt();
                let a = (outer - d + 0.5).clamp(0.0, 1.0);
                if a == 0.0 {
                    continue;
                }
                let (pr, pg, pb) = if d > rim { (20, 22, 31) } else { (r, g, b) };
                let i = ((y * SIZE + x) * 4) as usize;
                // Source-over onto the logo, in straight alpha.
                let da = px[i + 3] as f32 / 255.0;
                let oa = a + da * (1.0 - a);
                for (k, c) in [pr, pg, pb].into_iter().enumerate() {
                    let v = (c as f32 * a + px[i + k] as f32 * da * (1.0 - a)) / oa.max(1e-6);
                    px[i + k] = v.round() as u8;
                }
                px[i + 3] = (oa * 255.0).round() as u8;
            }
        }
        px
    }
}

/// The logo at 32×32, straight RGBA, rendered from
/// `crates/kenter-ui/skins/kenter/logo.svg` by `examples/render_icons.rs`.
const LOGO: &[u8; (SIZE * SIZE * 4) as usize] = include_bytes!("../../assets/tray-logo-32.rgba");

pub const SIZE: u32 = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_follows_the_state() {
        assert_eq!(Health::of(State::Online, false, false, true), Health::Green);
        assert_eq!(Health::of(State::Online, false, true, true), Health::Amber, "low fees");
        assert_eq!(Health::of(State::Online, false, false, false), Health::Amber, "no backup");
        assert_eq!(Health::of(State::Reconnecting, false, false, true), Health::Amber);
        assert_eq!(Health::of(State::AwaitingFunds, false, false, true), Health::Amber);
        assert_eq!(Health::of(State::Failed, false, false, true), Health::Red);
        assert_eq!(Health::of(State::Online, true, false, true), Health::Grey, "paused wins");
    }

    #[test]
    fn the_status_dot_sits_on_the_logo() {
        let px = Health::Green.rgba();
        assert_eq!(px.len(), (SIZE * SIZE * 4) as usize);
        let at = |x: u32, y: u32| {
            let i = ((y * SIZE + x) * 4) as usize;
            [px[i], px[i + 1], px[i + 2], px[i + 3]]
        };
        assert_eq!(at(SIZE - 8, SIZE - 8), [46, 160, 67, 255], "dot centre is the state colour");
        assert_eq!(at(0, 0), [LOGO[0], LOGO[1], LOGO[2], LOGO[3]], "the logo is untouched away from the dot");
        assert_ne!(Health::Red.rgba(), px, "states differ");
    }
}
