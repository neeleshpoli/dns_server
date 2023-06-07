use std::net::{Ipv4Addr, Ipv6Addr};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut PacketBuffer) -> Result<Packet> {
        let mut result = Packet::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = Question::new("".to_string(), RecordType::A);
            question.read(buffer);
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = Record::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = Record::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = Record::read(buffer)?;
            result.additionals.push(rec);
        }

        Ok(result)
    }
}

#[derive(Debug)]
pub struct PacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize
}

impl PacketBuffer {
    pub fn new() -> PacketBuffer {
        PacketBuffer {
            buf: [0; 512],
            pos: 0
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn read_name(&mut self, name: &mut String, max_jumps:u8) {
        let mut pos = self.pos();

        let mut jumped = false;
        let mut jumps_performed = 0;

        let mut delim = "";

        while jumps_performed <= max_jumps {
            let len = self.get(pos).unwrap();

            if (len& 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1).unwrap() as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                name.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize).unwrap();
                name.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos).unwrap();
        }
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_name(&mut self, name: &str) -> Result<()> {
        for label in name.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Header{
    pub id: u16,

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: Opcode,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    // Skip a bit for Z, reserved for future use
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,
}

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,

            recursion_desired: true,
            truncated_message: false,
            authoritative_answer: false,
            opcode: Opcode::Query,
            response: false,

            rescode: ResCode::NoError,
            checking_disabled: false,
            authed_data: true, 
            recursion_available: true,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = Opcode::read(&((a >> 3) & 0x0F));
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResCode::read(&(b & 0x0F));
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8) |
            ((self.truncated_message as u8) << 1) |
            ((self.authoritative_answer as u8) << 2) |
            ((self.opcode as u8) << 3) |
            ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8) |
            ((self.checking_disabled as u8) << 4) |
            ((self.authed_data as u8) << 5) |
            ((0 as u8) << 6) |
            ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Opcode {
    Query = 0,
    ReverseQuery = 1,
    Status = 2,

    // Add suport later
    // Notify = 4,
    // Update = 5,
    // DnsStatefulOperation = 6
}

impl Opcode {
    fn read(code: &u8) -> Opcode {
        match code {
            1 => Opcode::ReverseQuery,
            2 => Opcode::Status,
            _ => Opcode::Query
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    // Add all other Rescodes based on specification
}

impl ResCode {
    fn read(code: &u8) -> ResCode {
        match code {
            1 => ResCode::FormErr,
            2 => ResCode::ServFail,
            _ => ResCode::NoError
        }
    }
}

#[derive(Debug)]
pub enum Record {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32
    }
}

impl Record {
    pub fn read(buffer: &mut PacketBuffer) -> Result<Record> {
        let mut domain = String::new();
        buffer.read_name(&mut domain, 5);

        let qtype_num = buffer.read_u16()?;
        let qtype = RecordType::read(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            RecordType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(Record::A { domain, addr, ttl })
            }
            RecordType::AAAA => todo!(),
        }
    }
}

#[derive(Debug)]
pub enum RecordType {
    A = 1,
    AAAA = 28
    // Add other record types later
}

impl RecordType {
    pub fn read(num: u16) -> RecordType{
        match num {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            _ => RecordType::A
        }
    }
}

#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub record: RecordType
}

impl Question {
    pub fn new(name: String, record: RecordType) -> Question{
        Question {
            name,
            record
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) {
        buffer.read_name(&mut self.name, 5);
        self.record = RecordType::read(buffer.read_u16().unwrap()); // qtype
        let _ = buffer.read_u16(); // class
    }
}
