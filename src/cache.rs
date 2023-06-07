use std::{time::{SystemTime, Duration}, net::IpAddr};

struct DnsCacheEntry  {
    domain: String,
    record: String,
    ips: Vec<IpAddr>,
    ttl:Duration,
    timestamp: SystemTime
}

impl DnsCacheEntry {
    fn new(domain: String, record:String, ips: Vec<IpAddr>, ttl: Duration) -> Self {
        DnsCacheEntry {
            domain,
            record,
            ips,
            ttl,
            timestamp: SystemTime::now()
        }
    }
    fn alive(&self) -> bool {
        match self.timestamp.elapsed() {
            Ok(elapsed) => elapsed >= self.ttl,
            Err(_) => false, // Error occurred while calculating elapsed time
        }
    }
}