import { ContentInfo, EncapsulatedContent, EncapsulatedContentInfo, SignedData, CertificateSet, CertificateChoices } from "@peculiar/asn1-cms";
import { AsnConvert, AsnProp, AsnPropTypes, OctetString } from "@peculiar/asn1-schema";
import { LDIFParser } from "./ldif/parser.js";
import { base64ToBytes } from "./utils.js";

/** Wrapper for abstract decoder */
export class AbstractICAOPKDDecoder {
    /** CSCA certificates */
    public certificates!: CertificateSet;

    /**
     * Convert to PKCS#7
     * @param countryCode ISO 3166 Alpha 2 code (Optional)
     */
    toPKCS7(countryCode?: string): Uint8Array {
        const certificates = countryCode
        ? this.certificates.filter(i => i.certificate?.tbsCertificate.subject.some(j => j[0].type == "2.5.4.6" && j[0].value == countryCode.toUpperCase()))
        : this.certificates;

        return new Uint8Array(AsnConvert.serialize(new ContentInfo({
            contentType: "1.2.840.113549.1.7.2",
            content: AsnConvert.serialize(new SignedData({
                version: 1,
                encapContentInfo: new EncapsulatedContentInfo({
                    eContentType: "1.2.840.113549.1.7.1",
                    eContent: new EncapsulatedContent({ single: new OctetString() })
                }),
                certificates
            }))
        })));
    }
}

/**
 * CSCA master list (ASN.1)
 * 
 * Desribed by ICAO 9303 p.12 section 9.2
 * 
 * ```asn1
 * CscaMasterListVersion ::= INTEGER {v0(0)}
 * CscaMasterList ::= SEQUENCE {
 *    version   CscaMasterListVersion,
 *    certList  SET OF Certificate
 * }
 * ```
 */
export class CSCAMasterList extends AbstractICAOPKDDecoder {
    /** Master list version */
    @AsnProp({ type: AsnPropTypes.Integer })
    public version: number = 0;

    @AsnProp({ type: CertificateSet })
    public certificates: CertificateSet = new CertificateSet();

    /**
     * Parse CSCA master list
     * @param data Serialized data
     */
    static decode(data: Uint8Array): CSCAMasterList {
        const contentInfo = AsnConvert.parse(data, ContentInfo);
        const signedData = AsnConvert.parse(contentInfo.content, SignedData);

        return AsnConvert.parse(signedData.encapContentInfo.eContent!.single!, CSCAMasterList);
    }
}

/** CSCA/DSC master list (LDIF) */
export class LDIFMasterList extends AbstractICAOPKDDecoder {
    constructor(public certificates: CertificateSet) { super(); }

    /**
     * Parse CSCA master list
     * @param data Serialized data
     * @param countryCode ISO 3166 Alpha 2 code
     */
    static decode(data: string, countryCode: string): LDIFMasterList {
        const parsed = new LDIFParser(data, "dsc", countryCode).parse();
        const result = [];
        for(const i of parsed) {
            if(i.attributes && i.attributes["userCertificate;binary"]) 
                result.push(AsnConvert.parse(base64ToBytes(i.attributes["userCertificate;binary"][0]), CertificateChoices));
        }

        return new LDIFMasterList(result);
    }
}