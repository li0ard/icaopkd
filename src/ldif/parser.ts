// Very ugly, unstable and useless code

const ATTRTYPE_PATTERN = String.raw`[\w;.-]+(?:;[\w_-]+)*`;
const ATTRVALUE_PATTERN = String.raw`(([^,]|\\,)+|".*?")`;
const ATTR_PATTERN = `${ATTRTYPE_PATTERN}[ ]*=[ ]*${ATTRVALUE_PATTERN}`;
const RDN_PATTERN = `${ATTR_PATTERN}(?:[ ]*\\+[ ]*${ATTR_PATTERN})*[ ]*`;
const DN_PATTERN = `${RDN_PATTERN}(?:[ ]*,[ ]*${RDN_PATTERN})*[ ]*`;
const DN_REGEX = new RegExp(`^${DN_PATTERN}$`);

const is_dn = (s: string): boolean => {
    if (s === "") return true;

    const match = DN_REGEX.exec(s);
    return match !== null && match[0] === s;
}

export class LDIFParser {
    private lines: Uint8Array[];
    private lineIndex = 0;
    private encoding: string | null = "utf8";
    private strict = false;

    private textEncoder = new TextEncoder();
    private textDecoder = new TextDecoder();

    line_counter = 0;
    byte_counter = 0;
    records_read = 0;

    constructor(ldifString: string, private type?: string, private country?: string) {
        this.lines = ldifString.split(/\r?\n/).map(line => {
            const lineWithNewline = line + "\n";
            return this.textEncoder.encode(lineWithNewline);
        });
    }

    private readline(): Uint8Array | null {
        if (this.lineIndex >= this.lines.length) return null;
        return this.lines[this.lineIndex++];
    }

    parse() {
        const records = []
        for(const block of this.iterBlocks()) {
            const [dn, attributes] = this.parseEntryRecord(block);
            if (this.shouldIncludeRecord(dn)) records.push({ dn, attributes });
        }

        return records;
    }

    private shouldIncludeRecord(dn: string | null): boolean {
        if (!dn) return false;
        if (this.type && !dn.includes(`o=${this.type}`)) return false;
        if (this.country && !dn.includes(`c=${this.country}`)) return false;

        return true;
    }

    static stripLineSep(s: Uint8Array): Uint8Array {
        if (s.length >= 2 && s[s.length - 2] === 13 && s[s.length - 1] === 10) return s.subarray(0, -2);
        if (s.length >= 1 && s[s.length - 1] === 10)  return s.subarray(0, -1);

        return s;
    }

    private *iterUnfoldedLines(): Generator<Uint8Array> {
        let line = this.readline();

        while (line) {
            this.line_counter += 1;
            this.byte_counter += line.length;

            line = LDIFParser.stripLineSep(line);

            let nextline = this.readline();

            while (nextline && nextline.length > 0 && nextline[0] === 0x20) {
                const stripped = LDIFParser.stripLineSep(nextline).subarray(1);
                
                const concatenated: Uint8Array = new Uint8Array(line.length + stripped.length);
                concatenated.set(line);
                concatenated.set(stripped, line.length);
                line = concatenated;

                nextline = this.readline();
            }

            if (!(line.length > 0 && line[0] === 0x23)) yield line;

            line = nextline;
        }
    }

    private *iterBlocks(): Generator<Uint8Array[]> {
        let lines: Uint8Array[] = [];

        for (const line of this.iterUnfoldedLines()) {
            if (line.length > 0) lines.push(line);
            else if (lines.length > 0) {
                this.records_read += 1;
                yield lines;
                lines = [];
            }
        }

        if (lines.length > 0) {
            this.records_read += 1;
            yield lines;
        }
    }

    private decodeValue(attrType: string, attrValue: Uint8Array): [string, string | Uint8Array] {
        if (attrType === "dn") {
            try {
                return [attrType, this.textDecoder.decode(attrValue)];
            } catch (e) {
                if (this.strict) throw e;
                console.warn(e);
                return [attrType, this.textDecoder.decode(attrValue)];
            }
        }

        if (this.encoding) {
            try {
                const decoder = new TextDecoder(this.encoding);
                return [attrType, decoder.decode(attrValue)];
            } catch {}
        }

        return [attrType, attrValue];
    }

    private parseAttr(line: Uint8Array): [string, string | Uint8Array] {
        let colonPos = -1;
        for (let i = 0; i < line.length; i++) {
            if (line[i] === 0x3a) {
                colonPos = i;
                break;
            }
        }
        if (colonPos < 0) throw new Error("Invalid LDIF: no ':' in line");

        const attrType = this.textDecoder.decode(line.subarray(0, colonPos));
        const rest = line.subarray(colonPos);

        if (rest.length >= 2 && rest[0] === 0x3a && rest[1] === 0x3a) {
            const binaryString = this.textDecoder.decode(rest.subarray(2)).trim();
            const decoded = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                decoded[i] = binaryString.charCodeAt(i);
            }
            return this.decodeValue(attrType, decoded);
        }

        const raw = this.textDecoder.decode(rest.subarray(1)).trim();
        return this.decodeValue(attrType, this.textEncoder.encode(raw));
    }

    private error(msg: any) {
        if (this.strict) throw new Error(String(msg));
    }

    private checkDN(dn: string | null, value: string | Uint8Array) {
        if (dn !== null) this.error("Two lines starting with dn: in one record.");
        if (typeof value !== "string" || !is_dn(value)) this.error(`Invalid DN: ${value}`);
    }

    parseEntryRecord(lines: Uint8Array[]): [string | null, any] {
        let dn: string | null = null;
        const entry: Record<string, any[]> = {};

        for (const line of lines) {
            const [attrType, attrValue] = this.parseAttr(line);

            if (attrType === "version" && dn === null) continue;

            if (attrType === "dn") {
                this.checkDN(dn, attrValue);
                dn = attrValue as string;
                continue;
            }

            if (dn === null) {
                this.error(`Record does not start with dn: (${attrType})`);
                continue;
            }

            if (!entry[attrType]) entry[attrType] = [];
            entry[attrType].push(attrValue);
        }

        return [dn, entry];
    }
}