"use strict";
Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
const fs = require("fs");
const path = require("path");
require("csv-writer");
const cheerio = require("cheerio");
const winston = require("winston");
const dotenv = require("dotenv");
const node_crypto = require("node:crypto");
function _interopNamespaceDefault(e) {
  const n = Object.create(null, { [Symbol.toStringTag]: { value: "Module" } });
  if (e) {
    for (const k in e) {
      if (k !== "default") {
        const d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: () => e[k]
        });
      }
    }
  }
  n.default = e;
  return Object.freeze(n);
}
const cheerio__namespace = /* @__PURE__ */ _interopNamespaceDefault(cheerio);
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" })
  ]
});
dotenv.config();
const LOG_DIR = process.env.LOG_DIR || "./logs";
const RESULT_DIR = process.env.RESULT_DIR || "./res";
function replaceNbsps(str) {
  var re = new RegExp(String.fromCharCode(160), "g");
  return str.replaceAll(re, " ");
}
function ensureDirectoryExists(directory) {
  if (!fs.existsSync(directory)) {
    logger.info(`Creating directory: ${directory}`);
    fs.mkdirSync(directory, { recursive: true });
  }
}
ensureDirectoryExists(LOG_DIR);
ensureDirectoryExists(RESULT_DIR);
const BASE_URL = "https://helpx.adobe.com/security/products/magento.html";
function getMainData(table, $) {
  const row = $(table).find("tr:last td");
  const bulletinId = $(row[0]).text().trim();
  const datePublished = $(row[1]).text().trim();
  const priority = $(row[2]).text().trim();
  return {
    bulletinId,
    datePublished,
    priority
  };
}
function parseAffectedVersions($) {
  const affectedVersions = [];
  const affectedTable = $('h2:contains("Affected Versions")').parent().parent().next("div").find("table");
  if (affectedTable.length) {
    const rows = affectedTable.find("tr");
    let keys = [...$(rows[0]).find("th")].map((th) => replaceNbsps($(th).text().trim()));
    if (!keys.length) {
      keys = [...$(rows[0]).find("td")].map((th) => replaceNbsps($(th).text().trim()));
    }
    for (let i = 1; i < rows.length; i++) {
      const values = [...$(rows[i]).find("td")].map((td) => $(td).text().trim());
      const entry = {};
      keys.forEach((key, j) => {
        entry[key] = values[j];
      });
      affectedVersions.push(entry);
    }
  }
  return affectedVersions;
}
function parseSolution($) {
  const solutions = [];
  const solutionTable = $('h2:contains("Solution")').parent().parent().next("div").next("div").find("table");
  if (solutionTable.length) {
    const rows = solutionTable.find("tr");
    let keys = [...$(rows[0]).find("th")].map((th) => replaceNbsps($(th).text().trim()));
    if (!keys.length) {
      keys = [...$(rows[0]).find("td")].map((th) => replaceNbsps($(th).text().trim()));
    }
    for (let i = 1; i < rows.length; i++) {
      const values = [...$(rows[i]).find("td")].map((td) => $(td).text().trim());
      const entry = {};
      keys.forEach((key, j) => {
        entry[key] = values[j];
      });
      solutions.push(entry);
    }
  }
  return solutions;
}
async function parseOne(url) {
  try {
    if (!url) {
      logger.warn("URL is empty");
      return {};
    }
    if (url.startsWith("/")) {
      url = `https://helpx.adobe.com${url}`;
    }
    logger.info(`Parsing URL: ${url}`);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.text();
    const $ = cheerio__namespace.load(data);
    const tables = $("table");
    const vulnerabilitiesTable = tables[tables.length - 1];
    const res = [];
    const rows = $(vulnerabilitiesTable).find("tr");
    const basicData = getMainData(tables[0], $);
    let keys = [...$(rows[0]).find("td")].map((val) => replaceNbsps($(val).text().trim()));
    if (!keys.length) {
      keys = [...$(rows[0]).find("th")].map((val) => replaceNbsps($(val).text().trim()));
    }
    for (let i = 1; i < rows.length; i++) {
      const values = $(rows[i]).find("td");
      const entry = {};
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
      solutions
    };
  } catch (error) {
    handleFetchError(error, url);
    return {};
  }
}
function handleFetchError(error, url) {
  if (error instanceof Error) {
    logger.error(`Error parsing URL ${url}: ${error.message}`);
  } else {
    logger.error(`Unknown error occurred while parsing URL ${url}`);
  }
}
async function parseTable() {
  try {
    logger.info(`Fetching base URL: ${BASE_URL}`);
    const response = await fetch(BASE_URL);
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.text();
    const $ = cheerio__namespace.load(data);
    const rows = $("#root_content_flex_items_position_position-par_table_copy tr");
    const vulnerabilities = [];
    for (const row of rows.toArray()) {
      const columns = $(row).find("td");
      const link = $(columns[0]).find("a").attr("href");
      if (!link) {
        continue;
      }
      const vulnData = await parseOne(link);
      vulnerabilities.push({
        ...vulnData,
        link: link.startsWith("/") ? `https://helpx.adobe.com${link}` : link
      });
    }
    return vulnerabilities;
  } catch (error) {
    handleFetchError(error, BASE_URL);
    return [];
  }
}
function handleError(error, fileType) {
  if (error instanceof Error) {
    logger.error(`Error saving ${fileType} file: ${error.message}`);
  } else {
    logger.error(`Unknown error occurred while saving ${fileType} file`);
  }
}
function convertToISO(dateString) {
  if (!dateString) {
    return (/* @__PURE__ */ new Date()).toISOString();
  }
  dateString = replaceNbsps(dateString);
  const cleanedDate = dateString.replace(/(\d+)(st|nd|rd|th)/, "$1");
  const date = new Date(cleanedDate);
  if (isNaN(date.getTime())) {
    throw new Error(`Invalid date format: ${dateString}`);
  }
  return date.toISOString();
}
async function transformVulnerabilities(vulnerabilities) {
  var _a;
  const records = [];
  for (const vuln of vulnerabilities) {
    for (const item of vuln.vulns) {
      const magentoOpenSourceVersions = (_a = vuln.affectedVersions) == null ? void 0 : _a.filter((av) => av.Product.includes("Magento Open Source")).map((av2) => av2.Version.replaceAll("\n", " ").replaceAll("and earlier versions", "").trim().replaceAll("and earlier", "").replaceAll("(see note)", "").trim()).join(" ").split(" ").map((v) => v.trim()).join(" ");
      const record = {
        external_id: vuln.bulletinId || "",
        // id: Math.random().toString(16).slice(2),
        title: item["Vulnerability Category"] || "Unknown",
        description: item["Vulnerability Impact"] || null,
        cve: item["CVE number(s)"] || item["CVE numbers"] || null,
        cve_link: item["CVE number(s)"] || item["CVE numbers"] || null ? `https://nvd.nist.gov/vuln/detail/${item["CVE number(s)"] || item["CVE numbers"] || null}` : null,
        cvss_score: item["CVSS base score"] || null,
        // Optional, can be added later
        cvss_rating: ((rating) => {
          switch (rating) {
            case "Important":
              return "High";
            case "Moderate":
              return "Medium";
            case "Unknown":
              return "Low";
            default:
              return rating;
          }
        })(item["Severity"] || "Unknown"),
        software: magentoOpenSourceVersions || "Unknown",
        references: vuln.link || "",
        published_date: convertToISO(vuln.datePublished || null),
        updated_date: convertToISO(vuln.datePublished || null)
      };
      record["id"] = await getObjectHash(record);
      records.push(record);
    }
  }
  return records;
}
async function getObjectHash(obj) {
  const str = JSON.stringify(obj, Object.keys(obj).sort());
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await node_crypto.webcrypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return hashHex;
}
function saveVulnerabilities(records, date) {
  const jsonFilePath = path.join(RESULT_DIR, `magento-vulnerabilities.json`);
  try {
    const jsonString = JSON.stringify(records, null, 2);
    fs.writeFileSync(jsonFilePath, jsonString);
    logger.info(`Vulnerabilities saved to ${jsonFilePath}`);
  } catch (error) {
    handleError(error, "JSON");
  }
}
async function main() {
  logger.info("Starting the program...");
  try {
    const vulnerabilities = await parseTable();
    const date = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
    const transformedVulnerabilities = await transformVulnerabilities(vulnerabilities);
    saveVulnerabilities(transformedVulnerabilities, date);
    logger.info("Program completed successfully.");
  } catch (error) {
    handleFetchError(error, "main");
  }
}
if (require.main === module) {
  main();
}
exports.getMainData = getMainData;
exports.parseAffectedVersions = parseAffectedVersions;
exports.parseOne = parseOne;
exports.parseSolution = parseSolution;
