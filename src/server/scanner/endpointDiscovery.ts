import { ApiEndpoint } from '../../types/security';
import { ParsedOpenApi } from './openapiParser';

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'] as const;

export function discoverEndpoints(parsed: ParsedOpenApi): ApiEndpoint[] {
  const endpoints: ApiEndpoint[] = [];
  const { paths, globalSecurity, securitySchemes } = parsed;

  const defaultAuthType = Object.keys(securitySchemes).length > 0
    ? Object.keys(securitySchemes)[0]
    : 'Bearer JWT';

  for (const [pathKey, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    // Path-level parameters
    const pathParameters = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

    for (const methodKey of HTTP_METHODS) {
      const operation = pathItem[methodKey];
      if (!operation || typeof operation !== 'object') continue;

      const upperMethod = methodKey.toUpperCase() as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

      // Security requirement determination:
      // If operation.security is defined:
      //   if empty array `[]`, auth is explicitly disabled!
      //   if non-empty, auth is required with those schemes.
      // If operation.security is undefined:
      //   inherits globalSecurity.
      let requiresAuth = false;
      let authType = 'None';

      if (Array.isArray(operation.security)) {
        if (operation.security.length > 0) {
          requiresAuth = true;
          const firstSchemeKey = Object.keys(operation.security[0] || {})[0];
          authType = firstSchemeKey || defaultAuthType;
        } else {
          requiresAuth = false;
          authType = 'None';
        }
      } else if (globalSecurity && globalSecurity.length > 0) {
        requiresAuth = true;
        const firstSchemeKey = Object.keys(globalSecurity[0] || {})[0];
        authType = firstSchemeKey || defaultAuthType;
      }

      // Combine parameters
      const opParameters = Array.isArray(operation.parameters) ? operation.parameters : [];
      const combinedParams = [...pathParameters, ...opParameters];

      const formattedParameters: ApiEndpoint['parameters'] = combinedParams.map((param: any) => {
        return {
          name: param.name || 'param',
          in: (['path', 'query', 'header', 'body'].includes(param.in) ? param.in : 'query') as any,
          required: Boolean(param.required || param.in === 'path'),
          type: param.schema?.type || param.type || 'string',
          description: param.description
        };
      });

      // Extract schemas
      let requestBodySchema: string | undefined;
      if (operation.requestBody?.content?.['application/json']?.schema) {
        requestBodySchema = JSON.stringify(
          operation.requestBody.content['application/json'].schema,
          null,
          2
        );
      }

      let responseSchema: string | undefined;
      const okResponse = operation.responses?.['200'] || operation.responses?.['201'];
      if (okResponse?.content?.['application/json']?.schema) {
        responseSchema = JSON.stringify(
          okResponse.content['application/json'].schema,
          null,
          2
        );
      }

      // Auto-extract path params from template if missing from definition
      const pathMatches = pathKey.match(/\{([^}]+)\}/g);
      if (pathMatches) {
        for (const match of pathMatches) {
          const paramName = match.replace(/[{}]/g, '');
          if (!formattedParameters.some((p) => p.name === paramName && p.in === 'path')) {
            formattedParameters.unshift({
              name: paramName,
              in: 'path',
              required: true,
              type: 'string',
              description: `Path parameter ${paramName}`
            });
          }
        }
      }

      endpoints.push({
        id: `ep-${upperMethod.toLowerCase()}-${pathKey.replace(/[^a-zA-Z0-9]/g, '_')}`,
        method: upperMethod,
        path: pathKey,
        summary: operation.summary || `${upperMethod} ${pathKey}`,
        description: operation.description,
        requiresAuth,
        authType: requiresAuth ? authType : 'None',
        riskLevel: 'LOW',
        parameters: formattedParameters,
        requestBodySchema,
        responseSchema,
        findingsCount: 0,
        lastScanned: new Date().toISOString().replace('T', ' ').substring(0, 19),
        status: 'TESTED'
      });
    }
  }

  return endpoints;
}
