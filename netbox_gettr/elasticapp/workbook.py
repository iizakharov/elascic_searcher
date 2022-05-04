from datetime import timedelta, datetime


class ElkFilter:
    def time_delta(self, days):
        delta = timedelta(days=days)
        now = datetime.now()
        date_from = now - delta
        return now, date_from

    def __init__(self, arg, days, index):
        self.arg = arg
        self.days = days
        self.index = index
        self.indexes = self.make_index()
        self.date_now, self.date_from = self.time_delta(self.days)
        self.data = {}

    def make_index(self):
        indexes = ['osquery', 'logstash', 'kasper', 'dhcp', 'filebeat']
        index_arr = []
        print(self.index)
        if self.index not in indexes:
            return print('Не верно указан Индекс')
        if self.days <= 1:
            return [self.index + datetime.now().strftime('-%Y.%m.%d')]
        print('ok')
        for day in range(self.days):
            delta = timedelta(days=day)
            now = datetime.now()
            date = now - delta
            index_arr.append(self.index + date.strftime('-%Y.%m.%d'))
        return index_arr

    def get_index_form(self, any_filter=False):
        if any_filter:
            return self.any_filter_form()
        elif self.index == 'osquery':
            return self.osquery_filter_form()
        elif self.index == 'logstash':
            return self.logstash_filter_form()
        elif self.index == 'kasper':
            return self.kasper_filter_form()
        elif self.index == 'dhcp':
            return self.dhcp_filter_form()

    def osquery_filter_form(self):
        body_osquery = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "bool": {
                                            "should": [{"match": {"all_connections.local_address": self.arg}}],
                                            "minimum_should_match": 1
                                        }
                                    },
                                ],
                                "minimum_should_match": 1
                            }
                        },
                    ],
                }
            }
        }
        return body_osquery

    def logstash_filter_form(self):
        body_logstash = {
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30s",
                        "time_zone": "UTC",
                        "min_doc_count": 1
                    }
                }
            },
            "stored_fields": [
                "*"
            ],
            "script_fields": {},
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_all": {}
                        },
                        {
                            "exists": {
                                "field": "user_address"
                            }
                        },
                        {
                            "match_phrase": {
                                "user_address": self.arg
                            }
                        },
                    ],
                    "should": [],
                    "must_not": []
                }
            },
        }
        return body_logstash

    def kasper_filter_form(self):
        body_kasper = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match": {
                                                        "attack_source_ip": self.arg
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    },
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match": {
                                                        "attack_target_ip": self.arg
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                    ],
                }
            },
        }
        return body_kasper

    def dhcp_filter_form(self):
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "multi_match": {
                                "type": "best_fields",
                                "query": self.arg,
                                "lenient": True
                            }
                        },
                    ],
                }
            }
        }
        return body

    def any_filter_form(self):
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "multi_match": {
                                "type": "best_fields",
                                "query": self.arg,
                                "lenient": True
                            }
                        },
                    ],
                }
            }
        }
        return body

    def check_timedelta(self, old_request, new_request):
        new = datetime.strptime(new_request['@timestamp'], '%Y-%m-%d %H:%M')
        old = datetime.strptime(old_request['@timestamp'], '%Y-%m-%d %H:%M')
        if old == new:
            # print('Ровны !', new, old)
            return True
        elif new - old < timedelta(seconds=600):
            # print('Меньше 10 минут !', new, old)
            return True
        return False


class ElkMassIpFilter(ElkFilter):
    def __init__(self, arg, days, index):
        super().__init__(arg, days, index)
        self.arg = arg

    def get_index_form(self, any_filter=False):
        if self.index == 'osquery':
            return self.osquery_filter_form()
        elif self.index == 'filebeat':
            return self.filebeat_filter_form()

    def osquery_filter_form(self):
        arr = []
        body = {
            "query": {
                "bool": {
                    "filter": [
                    ],
                }
            }
        }
        for ip in self.arg:
            arr.append({"match_phrase": {"all_connections.remote_address": f"{ip}"}})
        body["query"]["bool"]["filter"] = [{'match_all': {}}, {'bool': {'should': [item for item in arr],
                                                                        'minimum_should_match': 1}}]

        return body

    def filebeat_filter_form(self):
        arr = []
        body = {
            "query": {
                "bool": {
                    "filter": [
                    ],
                }
            }
        }
        for ip in self.arg:
            arr.append({"match_phrase": {"destination.ip": f"{ip}"}})
        body["query"]["bool"]["filter"] = [{'match_all': {}}, {'bool': {'should': [item for item in arr],
                                                                        'minimum_should_match': 1}}]

        return body


class Incidents(ElkFilter):
    def __init__(self, index):
        self.filter = index
        self.index = 'osquery'
        self.arg = None
        self.index = None
        self.indexes = None
        self.date_now, self.date_from = None, None
        self.data = {}

    def get_index_form(self, any_filter=False):
        if any_filter:
            return self.any_filter_form()
        elif self.filter == 'mssec':
            return self.mssec_by_ip()
        elif self.filter == 'intranet':
            return self.intranet_internet()
        elif self.filter == 'messenger':
            return self.messenger()

    def mssec_by_ip(self):
        body = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "multi_match": {
                                            "type": "phrase",
                                            "query": "mssecsvc.exe",
                                            "lenient": True
                                        }
                                    },
                                    {
                                        "bool": {
                                            "filter": [
                                                {
                                                    "multi_match": {
                                                        "type": "phrase",
                                                        "query": "mssecsvr.exe",
                                                        "lenient": True
                                                    }
                                                },
                                                {
                                                    "bool": {
                                                        "filter": [
                                                            {
                                                                "bool": {
                                                                    "should": [
                                                                        {
                                                                            "match": {
                                                                                "avz_install": False
                                                                            }
                                                                        }
                                                                    ],
                                                                    "minimum_should_match": 1
                                                                }
                                                            },
                                                            {
                                                                "bool": {
                                                                    "should": [
                                                                        {
                                                                            "match": {
                                                                                "szi_install": False
                                                                            }
                                                                        }
                                                                    ],
                                                                    "minimum_should_match": 1
                                                                }
                                                            }
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "exists": {
                                "field": "all_connections.local_address"
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "szi_install": "true"
                            }
                        },
                        {
                            "match_phrase": {
                                "avz_install": "true"
                            }
                        }
                    ]
                }
            }
        }
        return body

    def intranet_internet(self):  # noqa: E501
        body = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "osquery_pack.keyword": "pack_windows-security-pack_all_connections"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    },
                                    {
                                        "bool": {
                                            "filter": [
                                                {
                                                    "bool": {
                                                        "must_not": {
                                                            "bool": {
                                                                "should": [
                                                                    {
                                                                        "query_string": {
                                                                            "fields": [
                                                                                "all_connections.remote_address.keyword"
                                                                            ],
                                                                            "query": "\\1\\0\\.*"
                                                                        }
                                                                    }
                                                                ],
                                                                "minimum_should_match": 1
                                                            }
                                                        }
                                                    }
                                                },
                                                {
                                                    "bool": {
                                                        "filter": [
                                                            {
                                                                "bool": {
                                                                    "must_not": {
                                                                        "bool": {
                                                                            "should": [
                                                                                {
                                                                                    "query_string": {
                                                                                        "fields": [
                                                                                            "all_connections.remote_address.keyword"  # noqa: E501
                                                                                        ],
                                                                                        "query": "\\1\\9\\2\\.\\1\\6\\8*"  # noqa: E501
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "minimum_should_match": 1
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            {
                                                                "bool": {
                                                                    "filter": [
                                                                        {
                                                                            "bool": {
                                                                                "must_not": {
                                                                                    "bool": {
                                                                                        "should": [
                                                                                            {
                                                                                                "query_string": {
                                                                                                    "fields": [
                                                                                                        "all_connections.remote_address.keyword"  # noqa: E501
                                                                                                    ],
                                                                                                    "query": "fe*"
                                                                                                }
                                                                                            }
                                                                                        ],
                                                                                        "minimum_should_match": 1
                                                                                    }
                                                                                }
                                                                            }
                                                                        },
                                                                        {
                                                                            "bool": {
                                                                                "filter": [
                                                                                    {
                                                                                        "bool": {
                                                                                            "must_not": {
                                                                                                "bool": {
                                                                                                    "should": [
                                                                                                        {
                                                                                                            "query_string": {  # noqa: E501
                                                                                                                "fields": [  # noqa: E501
                                                                                                                    "endpoint_ip1"  # noqa: E501
                                                                                                                ],
                                                                                                                "query": "\\1\\0\\.\\2\\5\\4\\.*"  # noqa: E501
                                                                                                            }
                                                                                                        }
                                                                                                    ],
                                                                                                    "minimum_should_match": 1  # noqa: E501
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    },
                                                                                    {
                                                                                        "bool": {
                                                                                            "filter": [
                                                                                                {
                                                                                                    "bool": {
                                                                                                        "must_not": {
                                                                                                            "bool": {
                                                                                                                "should": [  # noqa: E501
                                                                                                                    {
                                                                                                                        "query_string": {  # noqa: E501
                                                                                                                            "fields": [  # noqa: E501
                                                                                                                                "endpoint_ip1"  # noqa: E501
                                                                                                                            ],  # noqa: E501
                                                                                                                            "query": "\\1\\0\\.\\1\\5\\5\\.*"  # noqa: E501
                                                                                                                        }  # noqa: E501
                                                                                                                    }
                                                                                                                ],
                                                                                                                "minimum_should_match": 1  # noqa: E501
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "bool": {
                                                                                                        "filter": [
                                                                                                            {
                                                                                                                "bool": {  # noqa: E501
                                                                                                                    "should": [  # noqa: E501
                                                                                                                        {  # noqa: E501
                                                                                                                            "match": {  # noqa: E501
                                                                                                                                "all_connections.state": "ESTABLISHED"  # noqa: E501
                                                                                                                            }  # noqa: E501
                                                                                                                        }  # noqa: E501
                                                                                                                    ],
                                                                                                                    "minimum_should_match": 1  # noqa: E501
                                                                                                                }
                                                                                                            },
                                                                                                            {
                                                                                                                "bool": {  # noqa: E501
                                                                                                                    "filter": [  # noqa: E501
                                                                                                                        {  # noqa: E501
                                                                                                                            "bool": {  # noqa: E501
                                                                                                                                "should": [  # noqa: E501
                                                                                                                                    {  # noqa: E501
                                                                                                                                        "match": {  # noqa: E501
                                                                                                                                            "avz_install": False  # noqa: E501
                                                                                                                                        }  # noqa: E501
                                                                                                                                    }  # noqa: E501
                                                                                                                                ],  # noqa: E501
                                                                                                                                "minimum_should_match": 1  # noqa: E501
                                                                                                                            }  # noqa: E501
                                                                                                                        },  # noqa: E501
                                                                                                                        {  # noqa: E501
                                                                                                                            "bool": {  # noqa: E501
                                                                                                                                "should": [  # noqa: E501
                                                                                                                                    {  # noqa: E501
                                                                                                                                        "match": {  # noqa: E501
                                                                                                                                            "szi_install": False  # noqa: E501
                                                                                                                                        }  # noqa: E501
                                                                                                                                    }  # noqa: E501
                                                                                                                                ],  # noqa: E501
                                                                                                                                "minimum_should_match": 1  # noqa: E501
                                                                                                                            }  # noqa: E501
                                                                                                                        }  # noqa: E501
                                                                                                                    ]
                                                                                                                }
                                                                                                            }
                                                                                                        ]
                                                                                                    }
                                                                                                }
                                                                                            ]
                                                                                        }
                                                                                    }
                                                                                ]
                                                                            }
                                                                        }
                                                                    ]
                                                                }
                                                            }
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "exists": {
                                "field": "endpoint_ip2"
                            }
                        },
                        {
                            "exists": {
                                "field": "endpoint_ip1"
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "all_connections.name": "DlIpsService.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "svchost.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "backgroundTaskHost.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "SettingSyncHost.exe"
                            }
                        }
                    ]
                }
            }
        }
        return body

    def messenger(self):
        body = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "bool": {
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "osquery_pack.keyword": "pack_windows-security-pack_all_connections"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    },
                                    {
                                        "bool": {
                                            "filter": [
                                                {
                                                    "bool": {
                                                        "must_not": {
                                                            "bool": {
                                                                "should": [
                                                                    {
                                                                        "query_string": {
                                                                            "fields": [
                                                                                "all_connections.remote_address.keyword"
                                                                            ],
                                                                            "query": "\\1\\0\\.*"
                                                                        }
                                                                    }
                                                                ],
                                                                "minimum_should_match": 1
                                                            }
                                                        }
                                                    }
                                                },
                                                {
                                                    "bool": {
                                                        "filter": [
                                                            {
                                                                "bool": {
                                                                    "must_not": {
                                                                        "bool": {
                                                                            "should": [
                                                                                {
                                                                                    "query_string": {
                                                                                        "fields": [
                                                                                            "all_connections.remote_address.keyword"  # noqa: E501
                                                                                        ],
                                                                                        "query": "\\1\\9\\2\\.\\1\\6\\8*"  # noqa: E501
                                                                                    }
                                                                                }
                                                                            ],
                                                                            "minimum_should_match": 1
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            {
                                                                "bool": {
                                                                    "filter": [
                                                                        {
                                                                            "bool": {
                                                                                "must_not": {
                                                                                    "bool": {
                                                                                        "should": [
                                                                                            {
                                                                                                "query_string": {
                                                                                                    "fields": [
                                                                                                        "all_connections.remote_address.keyword"  # noqa: E501
                                                                                                    ],
                                                                                                    "query": "fe*"
                                                                                                }
                                                                                            }
                                                                                        ],
                                                                                        "minimum_should_match": 1
                                                                                    }
                                                                                }
                                                                            }
                                                                        },
                                                                        {
                                                                            "bool": {
                                                                                "filter": [
                                                                                    {
                                                                                        "bool": {
                                                                                            "must_not": {
                                                                                                "bool": {
                                                                                                    "should": [
                                                                                                        {
                                                                                                            "query_string": {  # noqa: E501
                                                                                                                "fields": [  # noqa: E501
                                                                                                                    "endpoint_ip1"  # noqa: E501
                                                                                                                ],
                                                                                                                "query": "\\1\\0\\.\\2\\5\\4\\.*"  # noqa: E501
                                                                                                            }
                                                                                                        }
                                                                                                    ],
                                                                                                    "minimum_should_match": 1  # noqa: E501
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    },
                                                                                    {
                                                                                        "bool": {
                                                                                            "filter": [
                                                                                                {
                                                                                                    "bool": {
                                                                                                        "must_not": {
                                                                                                            "bool": {
                                                                                                                "should": [  # noqa: E501
                                                                                                                    {
                                                                                                                        "query_string": {  # noqa: E501
                                                                                                                            "fields": [  # noqa: E501
                                                                                                                                "endpoint_ip1"  # noqa: E501
                                                                                                                            ],  # noqa: E501
                                                                                                                            "query": "\\1\\0\\.\\1\\5\\5\\.*"  # noqa: E501
                                                                                                                        }  # noqa: E501
                                                                                                                    }
                                                                                                                ],
                                                                                                                "minimum_should_match": 1  # noqa: E501
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                },
                                                                                                {
                                                                                                    "bool": {
                                                                                                        "should": [
                                                                                                            {
                                                                                                                "match": {  # noqa: E501
                                                                                                                    "all_connections.state": "ESTABLISHED"  # noqa: E501
                                                                                                                }
                                                                                                            }
                                                                                                        ],
                                                                                                        "minimum_should_match": 1  # noqa: E501
                                                                                                    }
                                                                                                }
                                                                                            ]
                                                                                        }
                                                                                    }
                                                                                ]
                                                                            }
                                                                        }
                                                                    ]
                                                                }
                                                            }
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.state": "ESTABLISHED"
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "match_phrase": {
                                            "all_connections.name": "Viber.exe"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "all_connections.name": "Telegram.exe"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                            "all_connections.name": "WhatsApp.exe"
                                        }
                                    }
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "exists": {
                                "field": "endpoint_ip1"
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [
                        {
                            "match_phrase": {
                                "all_connections.name": "DlIpsService.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "browser.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "opera.exe"
                            }
                        },
                        {
                            "match_phrase": {
                                "all_connections.name": "chrome.exe"
                            }
                        }
                    ]
                }
            }
        }
        return body


FORM = {
        "logstash": {
            "@timestamp": None,

            "user_address": None,

            "user_fio": None,

            "user_org": None,

            "user_agent": None,
        },
        "logstash_old": {
            "@timestamp": None,
            "timezone": None,
            "fio": None,
            "docflow_org_name": None,
            "HTTP_X_REAL_IP": None,
            "request_uri": None,
        },
        "osquery": {
            "@timestamp": None,
            "all_connections.hostname": None,
            "all_connections.local_address": None,
            "all_connections.name": None,
            "all_connections.remote_address": None,
            "all_connections.remote_port": None,
            "all_connections.state": None,
            "all_connections.avz_install": None,
            "all_connections.szi_install": None,
            "all_connections.logged_user": None
        },
        "po": {
            "@timestamp": None,

            "all_connections.hostname": None,
            "message.hostname": None,

            "all_connections.local_address": None,


            "message.avz_install": None,
            "all_connections.avz_install": None,
            "avz_install": None,

            "szi_install": None,
            "message.szi_install": None,
            "all_connections.szi_install": None,

            "yandex_version": None,
            "message.yandex_version": None,

            "dallas_version": None,
            "message.dallas_version": None,

            "all_connections.kaspersky_version": None,
            "message.kaspersky_version": None,

            "all_connections.logged_user": None,

            "all_connections.codename": None,
            "message.codename": None,
        },
        "kasper": {
            "@timestamp": None,

            "input.region": None,
            "sd.region": None,
            "ecs.region": None,
            "region": None,
            "agent_in_host.region": None,

            "input.attack_source_ip": None,
            "ecs.attack_source_ip": None,
            "attack_source_ip": None,
            "agent.attack_source_ip": None,
            "log.attack_source_ip": None,
            "sd.attack_source_ip": None,

            "input.attack_target_ip": None,
            "attack_target_ip": None,
            "event.hip": None,
            'log.attack_target_ip': None,
            "sd.attack_target_ip": None,

            "event.hdn": None,
            "event.p4": None,
            "event.p2": None,
            "event.p1": None,

            "event.etdn": None,
        },
        'dhcp': {
            "@timestamp": None,
            "hostname": None,
            "MAC_Address": None,
            "IP_Address": None,
            "Description": None,
            "Host_Name": None,
            "User_Name": None,
        },
        "osquery_ioc": {
            "@timestamp": None,
            'all_connections.hostname': None,
            "message.hostname": None,
            'hostname': None,

            'all_connections.local_address': None,
            'all_connections.logged_user': None,
            'all_connections.remote_address': None,
            'all_connections.remote_port': None,
            'all_connections.state': None
        },
        "filebeat": {
            "@timestamp": None,
            "source.ip": None,
            "source.port": None,
            "destination.ip": None,
            "destination.port": None,
            "network.transport": None,
            "network.bytes": None,
            "source.bytes": None,
        }
    }

INCIDENTS_FORM = {
    'mssec': {
        "@timestamp": None,
        "hostname": '-',
        "all_connections.local_address": None,
        "all_connections.remote_address": None,
        "all_connections.remote_port": None,
        "all_connections.path": None,
        "all_connections.state": None,
        "all_connections.avz_install": '-',
        "all_connections.szi_install": '-',
    },
    'intranet': {
        "@timestamp": None,
        "hostname": '-',
        "all_connections.endpoint_ip1": None,
        "all_connections.local_address": None,
        "all_connections.name": None,
        "all_connections.remote_address": None,
        "all_connections.remote_port": None,
        "all_connections.state": None,
        "all_connections.avz_install": '-',
        "all_connections.szi_install": '-',
        "all_connections.logged_user": '-'
    },
    'messenger': {
        "@timestamp": None,
        "hostname": '-',
        "all_connections.endpoint_ip1": None,
        "all_connections.local_address": None,
        "all_connections.name": None,
        "all_connections.remote_address": None,
        "all_connections.remote_port": None,
        "all_connections.state": None,
        "all_connections.avz_install": '-',
        "all_connections.szi_install": '-',
        "all_connections.logged_user": '-'
    }
}
