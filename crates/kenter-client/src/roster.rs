use stellar_xdr::curr::ScVal;
use tracing::debug;

use crate::error::ClientError;
use crate::mint::field;
use crate::tx::{
    TxBuilder, address_to_scval, bool_to_scval, option_to_scval, scval_to_bool, scval_to_i128,
    scval_to_u32,
    string_to_scval,
};

/// A roster record, decoded: the contract's `Node` minus its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub name: String,
    pub tunnel_endpoint: String,
    /// Stroops of the roster's pay token.
    pub staked: i128,
    pub joined_at: u32,
    pub last_heartbeat: u32,
    pub active: bool,
    /// Ledger at which the stake becomes withdrawable; `None` unless the
    /// node has called `leave`.
    pub unbonding_at: Option<u32>,
    pub volunteer: bool,
}

impl NodeInfo {
    /// Selectable by a print: active and not unbonding (the contract's
    /// `counted`).
    pub fn selectable(&self) -> bool {
        self.active && self.unbonding_at.is_none()
    }

    pub(crate) fn from_scval(val: &ScVal) -> Result<Self, ClientError> {
        let map = match val {
            ScVal::Map(Some(m)) => m,
            _ => return Err(ClientError::XdrDecode(format!("expected a Node map, got {val:?}"))),
        };
        let string = |name: &str| -> Result<String, ClientError> {
            match field(map, name)? {
                ScVal::String(s) => Ok(s.to_string()),
                other => Err(ClientError::XdrDecode(format!("`{name}`: expected String, got {other:?}"))),
            }
        };
        Ok(NodeInfo {
            name: string("name")?,
            tunnel_endpoint: string("tunnel_endpoint")?,
            staked: scval_to_i128(field(map, "staked")?)?,
            joined_at: scval_to_u32(field(map, "joined_at")?)?,
            last_heartbeat: scval_to_u32(field(map, "last_heartbeat")?)?,
            active: scval_to_bool(field(map, "active")?)?,
            unbonding_at: match field(map, "unbonding_at")? {
                ScVal::Void => None,
                v => Some(scval_to_u32(v)?),
            },
            volunteer: scval_to_bool(field(map, "volunteer")?)?,
        })
    }
}

/// Client for the kenter-roster Soroban contract.
pub struct RosterClient {
    tx: TxBuilder,
    contract_id: String,
}

impl RosterClient {
    pub fn new(tx: TxBuilder, contract_id: &str) -> Self {
        Self {
            tx,
            contract_id: contract_id.to_string(),
        }
    }

    pub fn tx(&self) -> &TxBuilder {
        &self.tx
    }

    pub fn tx_mut(&mut self) -> &mut TxBuilder {
        &mut self.tx
    }

    // ── State-changing methods ──

    /// Join the roster. Pays `min_stake` from the source account.
    ///
    /// The bond and nothing else: the roster charges no fee, because it
    /// has no admin who could collect one.
    pub async fn join(
        &mut self,
        name: &str,
        tunnel_endpoint: &str,
    ) -> Result<ScVal, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![
            caller,
            string_to_scval(name)?,
            string_to_scval(tunnel_endpoint)?,
        ];

        debug!(name, tunnel_endpoint, "roster join: submitting");
        let result = self.tx.invoke(&self.contract_id, "join", args).await?;

        let node = result
            .return_value
            .ok_or(ClientError::MissingReturnValue)?;

        debug!("roster join: success");
        Ok(node)
    }

    /// Join (or convert) as a **volunteer**: same bond as `join`, but the
    /// mint burns this node's fees instead of crediting them, and the
    /// choice is permanent for the address.
    ///
    /// A registered paid node converts in place; one that already
    /// volunteers is refused by the contract.
    pub async fn volunteer(
        &mut self,
        name: &str,
        tunnel_endpoint: &str,
    ) -> Result<ScVal, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![
            caller,
            string_to_scval(name)?,
            string_to_scval(tunnel_endpoint)?,
        ];

        debug!(name, tunnel_endpoint, "roster volunteer: submitting");
        let result = self.tx.invoke(&self.contract_id, "volunteer", args).await?;
        let node = result
            .return_value
            .ok_or(ClientError::MissingReturnValue)?;
        debug!("roster volunteer: success");
        Ok(node)
    }

    /// Leave the roster. Returns staked amount.
    pub async fn leave(&mut self) -> Result<u32, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![caller];

        debug!("roster leave: submitting");
        let result = self.tx.invoke(&self.contract_id, "leave", args).await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Reclaim the stake once unbonding has run out. Returns the payout.
    ///
    /// The contract pays the address that staked, and only on that
    /// address's own signature: a lost key strands the bond for good.
    pub async fn withdraw_stake(&mut self) -> Result<i128, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        debug!("roster withdraw_stake: submitting");
        let result = self
            .tx
            .invoke(&self.contract_id, "withdraw_stake", vec![caller])
            .await?;
        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }

    /// Send a heartbeat. Returns the current ledger sequence.
    pub async fn heartbeat(&mut self) -> Result<u32, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;
        let args = vec![caller];

        let result = self.tx.invoke(&self.contract_id, "heartbeat", args).await?;

        result
            .return_value
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Update node metadata. Pass None for fields you don't want to change.
    pub async fn update_node(
        &mut self,
        name: Option<&str>,
        tunnel_endpoint: Option<&str>,
        active: Option<bool>,
    ) -> Result<ScVal, ClientError> {
        let caller = address_to_scval(self.tx.source_address())?;

        let name_val = match name {
            Some(n) => option_to_scval(Some(string_to_scval(n)?)),
            None => option_to_scval(None),
        };
        let endpoint_val = match tunnel_endpoint {
            Some(e) => option_to_scval(Some(string_to_scval(e)?)),
            None => option_to_scval(None),
        };
        let active_val = match active {
            Some(a) => option_to_scval(Some(bool_to_scval(a))),
            None => option_to_scval(None),
        };

        let args = vec![caller, name_val, endpoint_val, active_val];

        let result = self.tx.invoke(&self.contract_id, "update_node", args).await?;

        result.return_value.ok_or(ClientError::MissingReturnValue)
    }

    // ── Read-only queries ──

    /// Check if an address is a roster member.
    pub async fn is_node(&mut self, address: &str) -> Result<bool, ClientError> {
        let args = vec![address_to_scval(address)?];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "is_node", args)
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_bool)
    }

    /// A node's terms: `None` if it is not in the selectable pool,
    /// otherwise `Some(volunteer)`. What the mint reads at `request_print`.
    pub async fn node_terms(&mut self, address: &str) -> Result<Option<bool>, ClientError> {
        let args = vec![address_to_scval(address)?];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "node_terms", args)
            .await?;
        match result {
            Some(ScVal::Void) | None => Ok(None),
            Some(ScVal::Bool(b)) => Ok(Some(b)),
            Some(other) => Err(ClientError::XdrDecode(format!(
                "unexpected node_terms result: {other:?}"
            ))),
        }
    }

    /// Look up a node's tunnel endpoint. Returns None if not on the roster.
    pub async fn lookup(&mut self, address: &str) -> Result<Option<String>, ClientError> {
        let args = vec![address_to_scval(address)?];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "lookup", args)
            .await?;

        match result {
            Some(ScVal::Void) | None => Ok(None),
            Some(ScVal::String(s)) => Ok(Some(s.to_string())),
            // Soroban Option<String> encoding: Vec([String]) or Vec([])
            Some(ScVal::Vec(Some(ref v))) => {
                if v.0.is_empty() {
                    Ok(None)
                } else if let Some(ScVal::String(s)) = v.0.first() {
                    Ok(Some(s.to_string()))
                } else {
                    Ok(None)
                }
            }
            Some(other) => Err(ClientError::XdrDecode(format!(
                "unexpected lookup result: {other:?}"
            ))),
        }
    }

    /// A node's full record, or `None` if the address never joined (or its
    /// record has been archived). Unlike [`Self::node_terms`] this answers
    /// for inactive and unbonding nodes too, which is what a node operator's
    /// status display needs.
    pub async fn get_node(&mut self, address: &str) -> Result<Option<NodeInfo>, ClientError> {
        let args = vec![address_to_scval(address)?];
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "get_node", args)
            .await?;
        match result {
            Some(ScVal::Void) | None => Ok(None),
            Some(ref v) => NodeInfo::from_scval(v).map(Some),
        }
    }

    /// Get the node count.
    pub async fn get_node_count(&mut self) -> Result<u32, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "get_node_count", vec![])
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_u32)
    }

    /// Get the minimum stake, in stroops of the roster's pay token.
    ///
    /// `i128`, not `u32`: a `u32` would cap the bond at 429.4967295 XLM,
    /// a ceiling on what a roster identity could be made to cost.
    /// Decoding it as a `u32` would fail at runtime rather than at compile
    /// time, which is why this is stated here and not left to the type
    /// checker.
    pub async fn min_stake(&mut self) -> Result<i128, ClientError> {
        let result = self
            .tx
            .simulate_invoke(&self.contract_id, "min_stake", vec![])
            .await?;

        result
            .as_ref()
            .ok_or(ClientError::MissingReturnValue)
            .and_then(scval_to_i128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ScMap, ScMapEntry, ScString, ScSymbol, StringM};

    fn sym(s: &str) -> ScVal {
        ScVal::Symbol(ScSymbol(StringM::try_from(s).unwrap()))
    }
    fn st(s: &str) -> ScVal {
        ScVal::String(ScString(StringM::try_from(s).unwrap()))
    }

    fn node(unbonding: ScVal, active: bool) -> ScVal {
        // Fields in the contract's (alphabetical) order, as the host
        // encodes a contracttype struct.
        let entries = vec![
            (sym("active"), ScVal::Bool(active)),
            (sym("address"), ScVal::Void),
            (sym("joined_at"), ScVal::U32(7)),
            (sym("last_heartbeat"), ScVal::U32(9)),
            (sym("name"), st("pi")),
            (sym("staked"), crate::tx::i128_to_scval(1_500_000_000)),
            (sym("tunnel_endpoint"), st("https://G.relay")),
            (sym("unbonding_at"), unbonding),
            (sym("volunteer"), ScVal::Bool(true)),
        ];
        ScVal::Map(Some(ScMap(
            entries
                .into_iter()
                .map(|(key, val)| ScMapEntry { key, val })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )))
    }

    #[test]
    fn a_node_record_decodes() {
        let n = NodeInfo::from_scval(&node(ScVal::Void, true)).unwrap();
        assert_eq!(n.name, "pi");
        assert_eq!(n.tunnel_endpoint, "https://G.relay");
        assert_eq!(n.staked, 1_500_000_000);
        assert_eq!((n.joined_at, n.last_heartbeat), (7, 9));
        assert!(n.volunteer && n.active && n.selectable());
        assert_eq!(n.unbonding_at, None);
    }

    #[test]
    fn an_unbonding_node_is_not_selectable() {
        let n = NodeInfo::from_scval(&node(ScVal::U32(500), true)).unwrap();
        assert_eq!(n.unbonding_at, Some(500));
        assert!(!n.selectable());
        let n = NodeInfo::from_scval(&node(ScVal::Void, false)).unwrap();
        assert!(!n.selectable());
    }
}

#[cfg(test)]
mod option_encoding {
    use crate::tx::{option_to_scval, bool_to_scval};
    use stellar_xdr::curr::ScVal;

    /// The host converts `Void` to `None` and a bare value to `Some`; a
    /// `Vec` is refused, which is how `update_node` trapped.
    #[test]
    fn options_encode_as_the_host_expects() {
        assert_eq!(option_to_scval(None), ScVal::Void);
        assert_eq!(option_to_scval(Some(bool_to_scval(false))), ScVal::Bool(false));
    }
}
