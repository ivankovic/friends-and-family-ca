/*  This file is part of Friends and Family CA.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
//! What a component asks the [`App`](super::app::App) to do.

use crate::ledger::{Holder, Reason, Target};

/// A person, device or agent the administrator has selected, by name. Owned, so that it outlives
/// the ledger it was read from: the ledger is re-read under it every few seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Person(String),
    Device { person: String, device: String },
    Agent(String),
}

impl Selection {
    pub fn target(&self) -> Target<'_> {
        match self {
            Selection::Person(person) => Target::Person(person),
            Selection::Device { .. } | Selection::Agent(_) => {
                Target::Holder(self.holder().expect("a device or an agent"))
            }
        }
    }

    /// The device or agent; a person holds no key of their own.
    pub fn holder(&self) -> Option<Holder<'_>> {
        match self {
            Selection::Person(_) => None,
            Selection::Device { person, device } => Some(Holder::Device { person, device }),
            Selection::Agent(agent) => Some(Holder::Agent(agent)),
        }
    }

    /// The name the selection itself goes by, as a rename starts from it.
    pub fn name(&self) -> &str {
        match self {
            Selection::Person(name) | Selection::Agent(name) => name,
            Selection::Device { device, .. } => device,
        }
    }
}

impl std::fmt::Display for Selection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Selection::Person(person) => write!(f, "{person}"),
            Selection::Device { person, device } => write!(f, "{person} · {device}"),
            Selection::Agent(agent) => write!(f, "{agent} · agent"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    /// Create the CA, valid for `years` as typed.
    CreateCa {
        name: String,
        years: String,
    },
    NextTab,
    PreviousTab,
    Help,
    CloseDialog,
    /// Open the form for a new person and their first device.
    AskNewPerson,
    /// Open the form for a new device, with the person filled in if one is selected.
    AskNewDevice {
        person: String,
    },
    AskNewAgent,
    AskRevoke(Selection),
    AskRename(Selection),
    /// Issue a certificate to a device or an agent, created if new, and write it to files.
    Issue(Selection),
    /// As `Issue`, to the first device of a person who must be new.
    IssueToNewPerson(Selection),
    Revoke(Selection, Reason),
    Rename(Selection, String),
    RefreshCrl,
    AskNginxSettings,
    /// The settings form's fields, in its order, as typed.
    SaveNginxSettings(Vec<String>),
    AskSiteMode(crate::nginx::Site),
    SetSiteMode(crate::nginx::Site, crate::nginx::Mode),
    TestNginx,
    /// Show the enrollment site's configuration, to write it.
    AskEnrollmentSite,
    /// Show the refresh timer's units, to set them up.
    AskTimer,
    InstallTimer,
    WriteEnrollmentSite,
    ShowInvite(crate::ledger::Invite),
    CancelInvite(crate::ledger::Serial),
}
