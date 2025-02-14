import fs from 'fs';
import path from 'path';
import { createObjectCsvWriter } from 'csv-writer';
import * as cheerio from 'cheerio';
import logger from './logger';
import {Bulletin, TableRow, VulnerabilityRecord} from './types/types'; // Updated import path
import dotenv from 'dotenv';
import * as crypto from "node:crypto";
// Load environment variables from .env file
dotenv.config();

// Get paths from environment variables
const LOG_DIR = process.env.LOG_DIR || './logs';
const RESULT_DIR = process.env.RESULT_DIR || './res';


function replaceNbsps(str: string) {
    var re = new RegExp(String.fromCharCode(160), "g");
    return str.replaceAll(re, " ");
}

// Ensure directories exist, create them if they don't
function ensureDirectoryExists(directory: string): void {
    if (!fs.existsSync(directory)) {
        logger.info(`Creating directory: ${directory}`);
        fs.mkdirSync(directory, { recursive: true });
    }
}

ensureDirectoryExists(LOG_DIR);
ensureDirectoryExists(RESULT_DIR);

const BASE_URL = 'https://helpx.adobe.com/security/products/magento.html';

// Function to extract main data from a table
export function getMainData(table: cheerio.Element, $: cheerio.Root): Partial<Bulletin> {
    const row = $(table).find('tr:last td');
    const bulletinId = $(row[0]).text().trim();
    const datePublished = $(row[1]).text().trim();
    const priority = $(row[2]).text().trim();

    return {
        bulletinId,
        datePublished,
        priority,
    };
}

// Parse "Affected Versions" table
export function parseAffectedVersions($: cheerio.Root): Record<string, string>[] {
    const affectedVersions: Record<string, string>[] = [];
    const affectedTable = $('h2:contains("Affected Versions")').parent().parent().next('div').find('table');
    //console.log('Affected Table, ', affectedTable.length)
    if (affectedTable.length) {
        const rows = affectedTable.find('tr');
        let keys = [...$(rows[0]).find('th')].map((th) => replaceNbsps($(th).text().trim()));
        if (!keys.length) {
            keys = [...$(rows[0]).find('td')].map((th) => replaceNbsps($(th).text().trim()));
        }
        for (let i = 1; i < rows.length; i++) {
            const values = [...$(rows[i]).find('td')].map((td) => $(td).text().trim());
            const entry: Record<string, string> = {};
            keys.forEach((key, j) => {
                entry[key] = values[j];
            });
            affectedVersions.push(entry);
        }

    }
    return affectedVersions;
}

// Parse "Solution" table
export function parseSolution($: cheerio.Root): Record<string, string>[] {
    const solutions: Record<string, string>[] = [];
    const solutionTable = $('h2:contains("Solution")').parent().parent().next('div').next('div').find('table');

    if (solutionTable.length) {
        const rows = solutionTable.find('tr');
        let keys = [...$(rows[0]).find('th')].map((th) => replaceNbsps($(th).text().trim()));
        if (!keys.length) {
            keys = [...$(rows[0]).find('td')].map((th) => replaceNbsps($(th).text().trim()));
        }
        for (let i = 1; i < rows.length; i++) {
            const values = [...$(rows[i]).find('td')].map((td) => $(td).text().trim());
            const entry: Record<string, string> = {};
            keys.forEach((key, j) => {
                entry[key] = values[j];
            });
            solutions.push(entry);
        }
    }

    return solutions;
}

// Parse a single vulnerability page
export async function parseOne(url: string): Promise<Partial<Bulletin>> {
    try {
        if (!url) {
            logger.warn('URL is empty');
            return {};
        }

        if (url.startsWith('/')) {
            url = `https://helpx.adobe.com${url}`;
        }

        logger.info(`Parsing URL: ${url}`);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.text();
        const $ = cheerio.load(data);

        const tables = $('table');
        const vulnerabilitiesTable = tables[tables.length - 1];

        const res: TableRow[] = [];
        const rows = $(vulnerabilitiesTable).find('tr');
        const basicData = getMainData(tables[0], $);

        let keys = [...$(rows[0]).find('td')].map((val) => replaceNbsps($(val).text().trim()));
        if (!keys.length) {
            keys = [...$(rows[0]).find('th')].map((val) => replaceNbsps($(val).text().trim()));
        }

        for (let i = 1; i < rows.length; i++) {
            const values = $(rows[i]).find('td');
            const entry: TableRow = {};
            keys.forEach((key, j) => {
                entry[key] = $(values[j]).text().trim();
            });
            res.push(entry);
        }

        const affectedVersions = parseAffectedVersions($);
        const solutions = parseSolution($);

        return {
            ...basicData,
            vulns: res,
            affectedVersions,
            solutions,
        };
    } catch (error) {
        handleFetchError(error, url);
        return {};
    }
}

// Handle fetch errors
function handleFetchError(error: unknown, url: string): void {
    if (error instanceof Error) {
        logger.error(`Error parsing URL ${url}: ${error.message}`);
    } else {
        logger.error(`Unknown error occurred while parsing URL ${url}`);
    }
}

// Parse the main table of vulnerabilities
async function parseTable(): Promise<Bulletin[]> {
    try {
        logger.info(`Fetching base URL: ${BASE_URL}`);
        const response = await fetch(BASE_URL);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.text();
        const $ = cheerio.load(data);

        const rows = $('#root_content_flex_items_position_position-par_table_copy tr');
        const vulnerabilities: Bulletin[] = [];

        for (const row of rows.toArray()) {
            const columns = $(row).find('td');
            const link = $(columns[0]).find('a').attr('href');

            if (!link) {
                continue;
            }

            const vulnData = await parseOne(link);
            vulnerabilities.push({
                ...vulnData,
                link: link.startsWith('/') ? `https://helpx.adobe.com${link}` : link,
            } as Bulletin);
        }

        return vulnerabilities;
    } catch (error) {
        handleFetchError(error, BASE_URL);
        return [];
    }
}

// Save results to JSON and CSV files
function saveResults(vulnerabilities: Bulletin[], date: string): void {
    const jsonFilePath = path.join(RESULT_DIR, `${date}.json`);
    const csvFilePath = path.join(RESULT_DIR, `${date}.csv`);

    // Save to JSON
    try {
        const jsonString = replaceNbsps(JSON.stringify(vulnerabilities, null, 2));
        fs.writeFileSync(jsonFilePath, jsonString);
        logger.info(`Data saved to ${jsonFilePath}`);
    } catch (error) {
        handleError(error, 'JSON');
    }

    // Save to CSV
    try {
        const csvWriter = createObjectCsvWriter({
            path: csvFilePath,
            header: Object.keys(vulnerabilities[0]?.vulns?.[0] || {}).map((key) => ({ id: key, title: key })),
        });

        const flatData = vulnerabilities.flatMap((vuln) =>
            vuln.vulns.map((v) => ({ ...v, bulletinId: vuln.bulletinId, datePublished: vuln.datePublished, priority: vuln.priority }))
        );

        csvWriter.writeRecords(flatData).then(() => {
            logger.info(`Data saved to ${csvFilePath}`);
        });
    } catch (error) {
        handleError(error, 'CSV');
    }
}

// Handle saving errors
function handleError(error: unknown, fileType: string): void {
    if (error instanceof Error) {
        logger.error(`Error saving ${fileType} file: ${error.message}`);
    } else {
        logger.error(`Unknown error occurred while saving ${fileType} file`);
    }
}
function convertToISO(dateString: string | null): string {
    if (!dateString){
        return (new Date()).toISOString();
    }
    dateString = replaceNbsps(dateString)
    const cleanedDate = dateString.replace(/(\d+)(st|nd|rd|th)/, "$1");
    // Создаем объект Date из строки
    const date = new Date(cleanedDate);

    // Проверяем, корректно ли распарсилась дата
    if (isNaN(date.getTime())) {
        throw new Error(`Invalid date format: ${dateString}`);
    }

    // Преобразуем в ISO-формат
    return date.toISOString();
}

// Transform vulnerabilities into Laravel-compatible format
async function transformVulnerabilities(vulnerabilities: Bulletin[]): Promise<VulnerabilityRecord[]> {
    const records: VulnerabilityRecord[] = [];

    for (const vuln of vulnerabilities) {
        for (const item of vuln.vulns) {
            // Filter affected versions to include only Magento Open Source 2
            const magentoOpenSourceVersions = vuln.affectedVersions
                ?.filter((av) => av.Product.includes('Magento Open Source'))
                .map((av2) => av2.Version.replaceAll('\n', ' ').replaceAll('and earlier versions', '').trim().replaceAll('and earlier', '').replaceAll('(see note)', '').trim())
                .join(' ').split(' ').map(v=>v.trim()).join(' ');

            const record: VulnerabilityRecord = {
                external_id: vuln.bulletinId || '',
                // id: Math.random().toString(16).slice(2),
                title: item['Vulnerability Category'] || 'Unknown',
                description: item['Vulnerability Impact'] || null,
                cve: item['CVE number(s)'] || item['CVE numbers'] || null,
                cve_link: (item['CVE number(s)'] || item['CVE numbers'] || null)
                    ? `https://nvd.nist.gov/vuln/detail/${item['CVE number(s)'] || item['CVE numbers'] || null}`
                    : null,
                cvss_score: item['CVSS base score'] || null, // Optional, can be added later
                cvss_rating: ((rating)=>{
                    switch (rating) {
                        case 'Important':
                            return 'High';
                            break;
                        case 'Moderate':
                            return 'Medium'
                        case 'Unknown':
                            return 'Low';
                        default:
                            return rating;
                    }
                })(item['Severity'] || 'Unknown'),
                software: magentoOpenSourceVersions || 'Unknown',
                references: vuln.link || '',
                published_date: convertToISO(vuln.datePublished || null),
                updated_date: convertToISO(vuln.datePublished || null),
            };
            record['id'] = await getObjectHash(record);
            records.push(record);
        }
    }

    return records;
}
async function getObjectHash(obj: VulnerabilityRecord) {
    // Преобразуем объект в строку
    const str = JSON.stringify(obj, Object.keys(obj).sort());

    // Преобразуем строку в ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(str);

    // Создаем хэш с использованием SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Преобразуем хэш в шестнадцатеричную строку
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Save vulnerabilities to JSON and CSV
function saveVulnerabilities(records: VulnerabilityRecord[], date: string): void {
    const jsonFilePath = path.join(RESULT_DIR, `magento-vulnerabilities.json`);
    // const csvFilePath = path.join(RESULT_DIR, `vulnerabilities_${date}.csv`);

    // Save to JSON
    try {
        const jsonString = JSON.stringify(records, null, 2);
        fs.writeFileSync(jsonFilePath, jsonString);
        logger.info(`Vulnerabilities saved to ${jsonFilePath}`);
    } catch (error) {
        handleError(error, 'JSON');
    }

    // Save to CSV
    // try {
    //     const csvWriter = createObjectCsvWriter({
    //         path: csvFilePath,
    //         header: [
    //             { id: 'external_id', title: 'EXTERNAL_ID' },
    //             { id: 'title', title: 'TITLE' },
    //             { id: 'description', title: 'DESCRIPTION' },
    //             { id: 'cve', title: 'CVE' },
    //             { id: 'cve_link', title: 'CVE_LINK' },
    //             { id: 'cvss_score', title: 'CVSS_SCORE' },
    //             { id: 'cvss_rating', title: 'CVSS_RATING' },
    //             { id: 'software', title: 'SOFTWARE' },
    //             { id: 'references', title: 'REFERENCES' },
    //             { id: 'published_date', title: 'PUBLISHED_DATE' },
    //             { id: 'updated_date', title: 'UPDATED_DATE' },
    //         ],
    //     });
    //
    //     csvWriter.writeRecords(records).then(() => {
    //         logger.info(`Vulnerabilities saved to ${csvFilePath}`);
    //     });
    // } catch (error) {
    //     handleError(error, 'CSV');
    // }
}
// Main function
async function main() {
    logger.info('Starting the program...');
    try {
        // const c = await parseOne('https://helpx.adobe.com/security/products/magento/apsb24-90.html');
        // return;
        const vulnerabilities = await parseTable();

        const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        const transformedVulnerabilities = await transformVulnerabilities(vulnerabilities);
        //saveResults(vulnerabilities, date);
        saveVulnerabilities(transformedVulnerabilities, date);
        logger.info('Program completed successfully.');
    } catch (error) {
        handleFetchError(error, 'main');
    }
}
if (require.main === module) {
    main();
}
// main();