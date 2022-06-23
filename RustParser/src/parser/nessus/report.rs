extern crate serde;
extern crate serde_xml_rs;

// #[macro_use]
// extern crate serde_derive;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NessusClientDatav2 {
    #[serde(rename = "Report")]
    pub report: Report,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub name: String,
    #[serde(rename = "ReportHost", default)]
    pub report_hosts: Vec<ReportHost>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReportHost {
    pub name: String,
    #[serde(rename = "HostProperties")]
    pub host_properties: HostProperties,
    #[serde(rename = "ReportItem")]
    pub report_items: Vec<ReportItem>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct HostProperties {
    #[serde(rename = "tag")]
    pub tags: Vec<Tag>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Tag {
    pub name: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReportItem {
    #[serde(rename = "pluginName")]
    pub plugin_name: String,
    #[serde(rename = "pluginID")]
    pub plugin_id: String,
    pub plugin_type: String,
    #[serde(default)]
    pub svc_name: String,
    pub severity: String,
    pub risk_factor: String,
    pub protocol: String,
    pub port: String,
    #[serde(default)]
    pub exploit_available: String,
    #[serde(default)]
    pub exploitability_ease: String,
    #[serde(default)]
    pub osvdb: Vec<String>,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub cvss3_base_score: String,
    #[serde(default)]
    pub cvss_base_score: String,
    #[serde(default)]
    pub see_also: String,
    pub description: String,
    pub solution: String,
    #[serde(default)]
    pub plugin_output: String,
    #[serde(default)]
    pub nessus_script: String,
    #[serde(default)]
    pub exploited_by_nessus: bool,
    #[serde(default)]
    pub metasploit_name: Vec<String>,
    #[serde(default)]
    pub exploit_framework_metasploit: bool,
    #[serde(default)]
    pub exploit_framework_canvas: bool,
    #[serde(default)]
    pub canvas_package: Vec<String>,
    #[serde(default)]
    pub exploit_framework_core: bool,
    #[serde(default)]
    pub fname: String,
    #[serde(default)]
    pub synopsis: String,
    #[serde(default)]
    pub attachment: Vec<Attachment>,
    #[serde(default)]
    pub patch_publication_date: String,
    #[serde(default)]
    pub vuln_publication_date: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    pub name: String,
}
