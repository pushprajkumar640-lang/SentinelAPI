import * as yaml from 'js-yaml';

export interface ParsedOpenApi {
  raw: any;
  title: string;
  version: string;
  description: string;
  servers: string[];
  baseUrl: string;
  paths: Record<string, any>;
  globalSecurity: any[];
  securitySchemes: Record<string, any>;
  format: 'json' | 'yaml';
}

export class OpenApiParseError extends Error {
  constructor(message: string, public readonly code: string = 'PARSE_ERROR') {
    super(message);
    this.name = 'OpenApiParseError';
  }
}

export function parseOpenApiSpec(input: string | object): ParsedOpenApi {
  if (!input) {
    throw new OpenApiParseError(
      'OpenAPI specification is empty. Please provide a valid JSON or YAML document.',
      'EMPTY_INPUT'
    );
  }

  let doc: any;
  let format: 'json' | 'yaml' = 'json';

  if (typeof input === 'object') {
    doc = input;
  } else {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new OpenApiParseError(
        'OpenAPI specification is empty. Please provide a valid JSON or YAML document.',
        'EMPTY_INPUT'
      );
    }

    // Try parsing as JSON first if it looks like JSON
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        doc = JSON.parse(trimmed);
        format = 'json';
      } catch (jsonErr: any) {
        // Fallback to YAML in case it has trailing commas or mixed syntax
        try {
          doc = yaml.load(trimmed);
          format = 'yaml';
        } catch {
          throw new OpenApiParseError(
            `Invalid JSON syntax in OpenAPI specification: ${jsonErr.message}`,
            'INVALID_JSON'
          );
        }
      }
    } else {
      // Try YAML parsing
      try {
        doc = yaml.load(trimmed);
        format = 'yaml';
      } catch (yamlErr: any) {
        throw new OpenApiParseError(
          `Invalid YAML syntax in OpenAPI specification: ${yamlErr.message}`,
          'INVALID_YAML'
        );
      }
    }
  }

  if (!doc || typeof doc !== 'object') {
    throw new OpenApiParseError(
      'OpenAPI specification must be a valid JSON or YAML object structure.',
      'INVALID_STRUCTURE'
    );
  }

  // Validate OpenAPI / Swagger version
  const isOpenApi3 = typeof doc.openapi === 'string' && doc.openapi.startsWith('3.');
  const isSwagger2 = typeof doc.swagger === 'string' && doc.swagger.startsWith('2.');

  if (!isOpenApi3 && !isSwagger2) {
    const foundVer = doc.openapi || doc.swagger || 'none';
    throw new OpenApiParseError(
      `Unsupported specification version (${foundVer}). SentinelAPI supports OpenAPI 3.x and Swagger 2.0.`,
      'UNSUPPORTED_VERSION'
    );
  }

  // Validate paths
  if (!doc.paths || typeof doc.paths !== 'object' || Object.keys(doc.paths).length === 0) {
    throw new OpenApiParseError(
      'OpenAPI specification does not contain any valid "paths" definitions.',
      'MISSING_PATHS'
    );
  }

  const title = doc.info?.title || 'API Target';
  const version = doc.info?.version || '1.0.0';
  const description = doc.info?.description || '';

  // Extract servers / base URL
  const servers: string[] = [];
  if (Array.isArray(doc.servers)) {
    for (const s of doc.servers) {
      if (s && typeof s.url === 'string') {
        servers.push(s.url);
      }
    }
  } else if (typeof doc.host === 'string') {
    const scheme = Array.isArray(doc.schemes) && doc.schemes[0] ? doc.schemes[0] : 'https';
    const basePath = typeof doc.basePath === 'string' ? doc.basePath : '';
    servers.push(`${scheme}://${doc.host}${basePath}`);
  }

  const baseUrl = servers[0] || 'http://127.0.0.1:3000/api/sandbox';

  // Extract security schemes
  const securitySchemes =
    doc.components?.securitySchemes || doc.securityDefinitions || {};

  const globalSecurity = Array.isArray(doc.security) ? doc.security : [];

  return {
    raw: doc,
    title,
    version,
    description,
    servers,
    baseUrl,
    paths: doc.paths,
    globalSecurity,
    securitySchemes,
    format
  };
}
