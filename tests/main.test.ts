import { parseOne, getMainData, parseAffectedVersions, parseSolution } from '../src/main';
import * as cheerio from 'cheerio';
import fs from 'fs';
import path from 'path';
import {ifError} from "node:assert";

// Helper function to load HTML from a file
function loadHtmlFixture(fileName: string): string {
    const filePath = path.join(__dirname, 'html', fileName);
    if (!fs.existsSync(filePath)) {
        throw new Error(`Fixture file not found: ${filePath}`);
    }
    return fs.readFileSync(filePath, 'utf-8');
}

describe('Parser Tests', () => {
    test('getMainData should extract main data correctly', () => {
        const html = loadHtmlFixture('mock-page.html'); //20-02
        const $ = cheerio.load(html);

        const table = $('table')[0];
        const result = getMainData(table, $);

        expect(result).toEqual({
            bulletinId: 'APSB20-02',
            datePublished: 'January 28, 2020',
            priority: '2',
        });
    });

    test('parseAffectedVersions should parse affected versions table correctly', () => {
        const html = loadHtmlFixture('mock-page.html'); //20-02
        const $ = cheerio.load(html);

        const result = parseAffectedVersions($);

        expect(result).toEqual([
            {
                "Product": "Magento Commerce",
                "Version": "2.3.3 and earlier versions",
                "Platform": "All"
            },
            {
                "Product": "Magento Open Source",
                "Version": "2.3.3 and earlier versions",
                "Platform": "All"
            },
            {
                "Product": "Magento Commerce",
                "Version": "2.2.10 and earlier versions",
                "Platform": "All"
            },
            {
                "Product": "Magento Open Source",
                "Version": "2.2.10 and earlier versions",
                "Platform": "All"
            },
            {
                "Product": "Magento Enterprise Edition",
                "Version": "1.14.4.3 and earlier versions",
                "Platform": "All"
            },
            {
                "Product": "Magento Community Edition",
                "Version": "1.9.4.3 and earlier versions",
                "Platform": "All"
            }
        ]);
    });

    test('parseSolution should parse solution table correctly', () => {
        const html = loadHtmlFixture('mock-page.html');
        const $ = cheerio.load(html);

        const result = parseSolution($);

        expect(result).toEqual([
            {
                "Product": "Magento Commerce",
                "Version": "2.3.4",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "2.3.4 Commerce"
            },
            {
                "Product": "Magento Open Source",
                "Version": "2.3.4",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "2.3.4 Open Source"
            },
            {
                "Product": "Magento Commerce",
                "Version": "2.2.11",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "2.2.11 Commerce"
            },
            {
                "Product": "Magento Open Source",
                "Version": "2.2.11",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "2.2.11 Open Source"
            },
            {
                "Product": "Magento Enterprise Edition",
                "Version": "1.14.4.4",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "1.14.4 EE"
            },
            {
                "Product": "Magento Community Edition",
                "Version": "1.9.4.4",
                "Platform": "All",
                "Priority Rating": "2",
                "Availability": "1.9.4.4 CE"
            }
        ]);
    });

    test('parseOne should handle a full page correctly', async () => {
        // Mock fetch to return the HTML from the fixture file
        const html = loadHtmlFixture('mock-page.html'); //20-02
        // const c = global.fetch
        // global.fetch = jest.fn((url, params) =>{
        //     if(url === 'https://example.com/mock-page'){
        //         return Promise.resolve({
        //             ok: true,
        //             text: () => Promise.resolve(html),
        //         })
        //     }
        //     else {
        //         return c(url, params);
        //     }
        // }
        // ) as jest.Mock;
        //@ts-ignore
        jest.spyOn(global, 'fetch').mockImplementationOnce((url, input)=>{
            return Promise.resolve({
                ok: true,
                text: () => Promise.resolve(html),
            })
        })
        const url = 'https://example.com/mock-page';
        const result = await parseOne(url);

        expect(result).toEqual(  {
            "bulletinId": "APSB20-02",
            "datePublished": "January 28, 2020",
            "priority": "2",
            "vulns": [
                {
                    "Vulnerability Category": "Stored cross-site scripting",
                    "Vulnerability Impact": "Sensitive information disclosure",
                    "Severity": "Important",
                    "Magento Bug ID": "PRODSECBUG-2543",
                    "CVE Numbers": "CVE-2020-3715"
                },
                {
                    "Vulnerability Category": "Stored cross-site scripting",
                    "Vulnerability Impact": "Sensitive information disclosure",
                    "Severity": "Important",
                    "Magento Bug ID": "PRODSECBUG-2599",
                    "CVE Numbers": "CVE-2020-3758"
                },
                {
                    "Vulnerability Category": "Deserialization of untrusted data",
                    "Vulnerability Impact": "Arbitrary code execution",
                    "Severity": "Critical",
                    "Magento Bug ID": "PRODSECBUG-2579",
                    "CVE Numbers": "CVE-2020-3716"
                },
                {
                    "Vulnerability Category": "Path traversal",
                    "Vulnerability Impact": "Sensitive information disclosure",
                    "Severity": "Important",
                    "Magento Bug ID": "PRODSECBUG-2632",
                    "CVE Numbers": "CVE-2020-3717"
                },
                {
                    "Vulnerability Category": "Security bypass",
                    "Vulnerability Impact": "Arbitrary code execution",
                    "Severity": "Critical",
                    "Magento Bug ID": "PRODSECBUG-2633",
                    "CVE Numbers": "CVE-2020-3718"
                },
                {
                    "Vulnerability Category": "SQL injection",
                    "Vulnerability Impact": "Sensitive information disclosure",
                    "Severity": "Critical",
                    "Magento Bug ID": "PRODSECBUG-2660",
                    "CVE Numbers": "CVE-2020-3719"
                }
            ],
            "affectedVersions": [
                {
                    "Product": "Magento Commerce",
                    "Version": "2.3.3 and earlier versions",
                    "Platform": "All"
                },
                {
                    "Product": "Magento Open Source",
                    "Version": "2.3.3 and earlier versions",
                    "Platform": "All"
                },
                {
                    "Product": "Magento Commerce",
                    "Version": "2.2.10 and earlier versions",
                    "Platform": "All"
                },
                {
                    "Product": "Magento Open Source",
                    "Version": "2.2.10 and earlier versions",
                    "Platform": "All"
                },
                {
                    "Product": "Magento Enterprise Edition",
                    "Version": "1.14.4.3 and earlier versions",
                    "Platform": "All"
                },
                {
                    "Product": "Magento Community Edition",
                    "Version": "1.9.4.3 and earlier versions",
                    "Platform": "All"
                }
            ],
            "solutions": [
                {
                    "Product": "Magento Commerce",
                    "Version": "2.3.4",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "2.3.4 Commerce"
                },
                {
                    "Product": "Magento Open Source",
                    "Version": "2.3.4",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "2.3.4 Open Source"
                },
                {
                    "Product": "Magento Commerce",
                    "Version": "2.2.11",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "2.2.11 Commerce"
                },
                {
                    "Product": "Magento Open Source",
                    "Version": "2.2.11",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "2.2.11 Open Source"
                },
                {
                    "Product": "Magento Enterprise Edition",
                    "Version": "1.14.4.4",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "1.14.4 EE"
                },
                {
                    "Product": "Magento Community Edition",
                    "Version": "1.9.4.4",
                    "Platform": "All",
                    "Priority Rating": "2",
                    "Availability": "1.9.4.4 CE"
                }
            ],
        });
    });
});