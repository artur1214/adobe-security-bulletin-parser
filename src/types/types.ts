// types.ts
export interface Bulletin {
    bulletinId: string;
    datePublished: string;
    priority: string;
    link: string;
    vulns: Record<string, string>[];
    solutions: Record<string, string>[];
    affectedVersions: Record<string, string>[];
}
export interface Vulnerability {
    "Vulnerability Category"?: string
    "Vulnerability Impact"?: string
    "Severity"?: string
    "Pre-authentication"?: string
    "Admin privileges required"?: string
    "Magento Bug ID"?: string
    "CVE numbers"?: string
    "CVSS base score"?: string,
    "CVSS vector"?: string
}
export interface VulnerabilityRecord {
    id?: string; //Just Random ID
    external_id: string; // Bulletin ID
    title: string; // Vulnerability Category
    description: string | null; // Vulnerability Impact
    cve: string | null; // CVE number
    cve_link: string | null; // Link to CVE (if available)
    cvss_score: string | null; // CVSS score (optional)
    cvss_rating: string | null; // CVSS rating (optional)
    software: string; // Product name
    references: string; // Link to the bulletin
    published_date: string | null; // Date Published
    updated_date: string | null; // Can be null or the same as published_date
}
export interface TableRow {
    [key: string]: string;
}