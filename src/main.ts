import fs from 'fs';
import path from 'path';
import { createObjectCsvWriter } from 'csv-writer';
import cheerio from 'cheerio';
import logger from './logger';
import { Vulnerability, TableRow } from './types/types'; // Updated import path
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Get paths from environment variables
const LOG_DIR = process.env.LOG_DIR || './logs';
const RESULT_DIR = process.env.RESULT_DIR || './res';

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
function getMainData(table: cheerio.Element, $: cheerio.Root): Partial<Vulnerability> {
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
function parseAffectedVersions($: cheerio.Root): Record<string, string>[] {
    const affectedVersions: Record<string, string>[] = [];
    const affectedTable = $('h2:contains("Affected Versions")').parent().parent().next('div').find('table');
    //console.log('Affected Table, ', affectedTable.length)
    if (affectedTable.length) {
        const rows = affectedTable.find('tr');
        const keys = [...$(rows[0]).find('th')].map((th) => $(th).text().trim());

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
function parseSolution($: cheerio.Root): Record<string, string>[] {
    const solutions: Record<string, string>[] = [];
    const solutionTable = $('h2:contains("Solution")').parent().parent().next('div').next('div').find('table');

    if (solutionTable.length) {
        const rows = solutionTable.find('tr');
        const keys = [...$(rows[0]).find('th')].map((th) => $(th).text().trim());

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
async function parseOne(url: string): Promise<Partial<Vulnerability>> {
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

        let keys = [...$(rows[0]).find('td')].map((val) => $(val).text().trim());
        if (!keys.length) {
            keys = [...$(rows[0]).find('th')].map((val) => $(val).text().trim());
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
async function parseTable(): Promise<Vulnerability[]> {
    try {
        logger.info(`Fetching base URL: ${BASE_URL}`);
        const response = await fetch(BASE_URL);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.text();
        const $ = cheerio.load(data);

        const rows = $('#root_content_flex_items_position_position-par_table_copy tr');
        const vulnerabilities: Vulnerability[] = [];

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
            } as Vulnerability);
        }

        return vulnerabilities;
    } catch (error) {
        handleFetchError(error, BASE_URL);
        return [];
    }
}

// Save results to JSON and CSV files
function saveResults(vulnerabilities: Vulnerability[], date: string): void {
    const jsonFilePath = path.join(RESULT_DIR, `${date}.json`);
    const csvFilePath = path.join(RESULT_DIR, `${date}.csv`);

    // Save to JSON
    try {
        const jsonString = JSON.stringify(vulnerabilities, null, 2);
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

// Main function
async function main() {
    logger.info('Starting the program...');
    try {
        // const c = await parseOne('https://helpx.adobe.com/security/products/magento/apsb24-90.html');
        // return;
        const vulnerabilities = await parseTable();

        const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        saveResults(vulnerabilities, date);

        logger.info('Program completed successfully.');
    } catch (error) {
        handleFetchError(error, 'main');
    }
}

main();