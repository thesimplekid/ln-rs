use std::path::PathBuf;
use std::time::SystemTime;

#[cfg(feature = "cln")]
use cln_rpc::model::responses::ListinvoicesInvoicesStatus as CLNInvoiceStatus;
#[cfg(feature = "greenlight")]
use gl_client::pb::cln::listinvoices_invoices::ListinvoicesInvoicesStatus as GlInvoiceStatus;
#[cfg(feature = "ldk")]
use ldk_node::PaymentStatus;
use ln_rs_models::InvoiceStatus;

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or(0)
}

pub fn expand_path(path: &str) -> Option<PathBuf> {
    if path.starts_with('~') {
        if let Some(home_dir) = dirs::home_dir().as_mut() {
            let remainder = &path[2..];
            home_dir.push(remainder);
            let expanded_path = home_dir;
            Some(expanded_path.clone())
        } else {
            None
        }
    } else {
        Some(PathBuf::from(path))
    }
}

#[cfg(feature = "cln")]
pub fn cln_invoice_status_to_status(status: CLNInvoiceStatus) -> InvoiceStatus {
    match status {
        CLNInvoiceStatus::UNPAID => InvoiceStatus::Unpaid,
        CLNInvoiceStatus::PAID => InvoiceStatus::Paid,
        CLNInvoiceStatus::EXPIRED => InvoiceStatus::Expired,
    }
}

#[cfg(feature = "greenlight")]
pub fn gln_invoice_status_to_status(status: GlInvoiceStatus) -> InvoiceStatus {
    match status {
        GlInvoiceStatus::Unpaid => InvoiceStatus::Unpaid,
        GlInvoiceStatus::Paid => InvoiceStatus::Paid,
        GlInvoiceStatus::Expired => InvoiceStatus::Expired,
    }
}

#[cfg(feature = "ldk")]
pub fn ldk_payment_status(status: PaymentStatus) -> InvoiceStatus {
    match status {
        PaymentStatus::Pending => InvoiceStatus::Unpaid,
        PaymentStatus::Succeeded => InvoiceStatus::Paid,
        PaymentStatus::Failed => InvoiceStatus::Expired,
    }
}
