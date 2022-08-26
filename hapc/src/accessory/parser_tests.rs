#[cfg(test)]
mod tests {
    use crate::accessory::parser::parse_accessory_json;

    #[test]
    fn response_parser() {
        let response_data = r#"
        {
            "accessories": [
                {
                    "aid": 1,
                    "services": [
                        {
                            "iid": 1,
                            "type": "3E",
                            "characteristics": [
                                {
                                    "iid": 2,
                                    "type": "14",
                                    "perms": [
                                        "pw"
                                    ],
                                    "format": "bool"
                                },
                                {
                                    "iid": 3,
                                    "type": "20",
                                    "perms": [
                                        "pr"
                                    ],
                                    "format": "string",
                                    "value": ""
                                },
                                {
                                    "iid": 4,
                                    "type": "21",
                                    "perms": [
                                        "pr"
                                    ],
                                    "format": "string",
                                    "value": ""
                                },
                                {
                                    "iid": 5,
                                    "type": "23",
                                    "perms": [
                                        "pr"
                                    ],
                                    "format": "string",
                                    "value": "Bridge"
                                },
                                {
                                    "iid": 6,
                                    "type": "30",
                                    "perms": [
                                        "pr"
                                    ],
                                    "format": "string",
                                    "value": "default"
                                },
                                {
                                    "iid": 7,
                                    "type": "52",
                                    "perms": [
                                        "pr"
                                    ],
                                    "format": "string",
                                    "value": ""
                                }
                            ]
                        },
                        {
                            "iid": 8,
                            "type": "A2",
                            "characteristics": [
                                {
                                    "iid": 9,
                                    "type": "37",
                                    "perms": [
                                        "pr",
                                        "ev"
                                    ],
                                    "format": "string",
                                    "value": "01.01.00"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        "#;
        let r = parse_accessory_json(response_data.to_string());
        assert!(r.is_ok(), "{}", true);
    }
}
