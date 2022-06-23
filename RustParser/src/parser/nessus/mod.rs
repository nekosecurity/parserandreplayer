pub mod report;
use serde_xml_rs::from_str;
use std::fs;
use std::path::Path;
use std::process::exit;

fn prepare(filename: String) -> String {
    if Path::new(&filename).exists() {
        let contents = fs::read_to_string(filename).expect("Something went wrong reading the file");
        contents
    } else {
        println!("File not found");
        exit(-1);
    }
}

use cpython::{PyDict, PyResult, Python, ToPyObject};

pub fn parse(filename: String) -> PyResult<report::NessusClientDatav2> {
    let contents = prepare(filename);
    let report = from_str(contents.as_str());

    Ok(report.unwrap())
}

impl ToPyObject for report::NessusClientDatav2 {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "report", &self.report).unwrap();
        dict
    }
}

impl ToPyObject for report::Report {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "name", &self.name).unwrap();
        dict.set_item(py, "report_host", &self.report_hosts)
            .unwrap();
        dict
    }
}

impl ToPyObject for report::ReportHost {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "ip", &self.name).unwrap();
        dict.set_item(py, "host_properties", &self.host_properties)
            .unwrap();
        dict.set_item(py, "report_items", &self.report_items)
            .unwrap();
        dict
    }
}

impl ToPyObject for report::HostProperties {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "tags", &self.tags).unwrap();
        dict
    }
}

impl ToPyObject for report::Tag {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "name", &self.name).unwrap();
        dict.set_item(py, "value", &self.value).unwrap();
        dict
    }
}

impl ToPyObject for report::ReportItem {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "pluginName", &self.plugin_name).unwrap();
        dict.set_item(py, "pluginID", &self.plugin_id).unwrap();
        dict.set_item(py, "plugin_type", &self.plugin_type).unwrap();
        dict.set_item(py, "svc_name", &self.svc_name).unwrap();
        dict.set_item(py, "severity", &self.severity).unwrap();
        dict.set_item(py, "risk_factor", &self.risk_factor).unwrap();
        dict.set_item(py, "protocol", &self.protocol).unwrap();
        dict.set_item(py, "port", &self.port).unwrap();
        dict.set_item(py, "exploit_available", &self.exploit_available)
            .unwrap();
        dict.set_item(py, "exploitability_ease", &self.exploitability_ease)
            .unwrap();
        dict.set_item(py, "osvdb", &self.osvdb).unwrap();
        dict.set_item(py, "cve", &self.cve).unwrap();
        dict.set_item(py, "cvss3_base_score", &self.cvss3_base_score)
            .unwrap();
        dict.set_item(py, "cvss_base_score", &self.cvss_base_score)
            .unwrap();
        dict.set_item(py, "see_also", &self.see_also).unwrap();
        dict.set_item(py, "description", &self.description).unwrap();
        dict.set_item(py, "solution", &self.solution).unwrap();
        dict.set_item(py, "plugin_output", &self.plugin_output)
            .unwrap();
        dict.set_item(py, "nessus_script", &self.nessus_script)
            .unwrap();
        dict.set_item(py, "exploited_by_nessus", &self.exploited_by_nessus)
            .unwrap();
        dict.set_item(py, "metasploit", &self.exploit_framework_metasploit)
            .unwrap();
        dict.set_item(py, "metasploit_name", &self.metasploit_name)
            .unwrap();
        dict.set_item(py, "canvas", &self.exploit_framework_canvas)
            .unwrap();
        dict.set_item(py, "canvas_package", &self.canvas_package)
            .unwrap();
        dict.set_item(py, "core", &self.exploit_framework_core)
            .unwrap();
        dict.set_item(py, "d2_elliot", &self.exploit_framework_d2_elliot)
            .unwrap();
        dict.set_item(py, "d2_elliot_name", &self.d2_elliot_name)
            .unwrap();
        dict.set_item(py, "nessus_script", &self.fname).unwrap();
        dict.set_item(py, "synopsis", &self.synopsis).unwrap();
        dict.set_item(py, "attachment", &self.attachment).unwrap();
        dict.set_item(py, "patch_publication_date", &self.patch_publication_date)
            .unwrap();
        dict.set_item(py, "vuln_publication_date", &self.vuln_publication_date)
            .unwrap();
        dict
    }
}

impl ToPyObject for report::Attachment {
    type ObjectType = PyDict;

    fn to_py_object(&self, py: Python) -> PyDict {
        let dict = PyDict::new(py);
        dict.set_item(py, "name", &self.name).unwrap();
        dict
    }
}
