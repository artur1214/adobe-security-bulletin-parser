// types.ts
export interface Vulnerability {
    bulletinId: string;
    datePublished: string;
    priority: string;
    link: string;
    vulns: Record<string, string>[];
    solutions: Record<string, string>[];
    affectedVersions: Record<string, string>[];
}

export interface TableRow {
    [key: string]: string;
}