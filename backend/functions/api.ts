import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractAuthContext, requirePermission, Role } from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'SalesDataQualitySystem';

interface AuditLog {
  pk: string;
  sk: string;
  userId: string;
  userName: string;
  operationType: string;
  targetTable: string;
  targetRecordId?: string;
  operationContent: string;
  changesBefore?: Record<string, unknown>;
  changesAfter?: Record<string, unknown>;
  operationStatus: string;
  errorMessage?: string;
  ipAddress?: string;
  sessionId?: string;
  createdAt: string;
}

function getCurrentTimestamp(): string {
  return new Date().toISOString();
}

function generateId(): string {
  return randomUUID();
}

async function createAuditLog(
  userId: string,
  userName: string,
  operationType: string,
  targetTable: string,
  targetRecordId: string | undefined,
  operationContent: string,
  operationStatus: string,
  changesBefore?: Record<string, unknown>,
  changesAfter?: Record<string, unknown>,
  errorMessage?: string,
  ipAddress?: string,
  sessionId?: string
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${getCurrentTimestamp()}#${generateId()}`,
    userId,
    userName,
    operationType,
    targetTable,
    targetRecordId,
    operationContent,
    changesBefore,
    changesAfter,
    operationStatus,
    errorMessage,
    ipAddress,
    sessionId,
    createdAt: getCurrentTimestamp(),
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

function createErrorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error: message }),
  };
}

function createSuccessResponse(
  statusCode: number,
  data: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'READ_ALL');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        Limit: 100,
      })
    );

    return createSuccessResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
      scannedCount: result.ScannedCount || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'BULK_IMPORT');

    if (!event.body) {
      return createErrorResponse(400, 'Request body is required');
    }

    const { items } = JSON.parse(event.body) as { items: Record<string, unknown>[] };

    if (!Array.isArray(items) || items.length === 0) {
      return createErrorResponse(400, 'items array is required and must not be empty');
    }

    const enrichedItems = items.map((item) => ({
      ...item,
      id: item.id || generateId(),
      createdAt: item.createdAt || getCurrentTimestamp(),
      updatedAt: item.updatedAt || getCurrentTimestamp(),
      createdBy: item.createdBy || authContext.userId,
      updatedBy: item.updatedBy || authContext.userId,
    }));

    const chunks: Record<string, unknown>[][] = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    let importedCount = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const writeRequests = chunk.map((item) => ({
        PutRequest: {
          Item: {
            pk: { S: `${tableIndex}#${item.id}` },
            sk: { S: `${item.id}` },
            ...Object.entries(item).reduce(
              (acc, [key, value]) => {
                if (value === null || value === undefined) {
                  return acc;
                }
                if (typeof value === 'string') {
                  acc[key] = { S: value };
                } else if (typeof value === 'number') {
                  acc[key] = { N: String(value) };
                } else if (typeof value === 'boolean') {
                  acc[key] = { BOOL: value };
                } else if (value instanceof Date) {
                  acc[key] = { S: value.toISOString() };
                } else {
                  acc[key] = { S: JSON.stringify(value) };
                }
                return acc;
              },
              {} as Record<string, unknown>
            ),
          },
        },
      }));

      const batchParams: BatchWriteItemCommandInput = {
        RequestItems: {
          [TABLE_NAME]: writeRequests,
        },
      };

      try {
        const response = await client.send(new BatchWriteItemCommand(batchParams));
        importedCount += chunk.length - (response.UnprocessedItems?.[TABLE_NAME]?.length || 0);

        if (response.UnprocessedItems?.[TABLE_NAME]?.length) {
          errors.push(`${response.UnprocessedItems[TABLE_NAME].length} items failed to write`);
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(errorMsg);
      }
    }

    await createAuditLog(
      authContext.userId,
      authContext.userName,
      'BULK_IMPORT',
      tableIndex,
      undefined,
      `Bulk imported ${importedCount} items`,
      'SUCCESS',
      undefined,
      { importedCount, totalItems: items.length },
      errors.length > 0 ? errors.join('; ') : undefined
    );

    return createSuccessResponse(200, {
      imported: importedCount,
      failed: items.length - importedCount,
      errors,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

async function handleGetResourceById(
  event: APIGatewayProxyEvent,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'READ_ALL');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return createErrorResponse(400, 'Resource ID is required');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `RESOURCE#${resourceId}`,
          sk: resourceId,
        },
      })
    );

    if (!result.Item) {
      return createErrorResponse(404, 'Resource not found');
    }

    return createSuccessResponse(200, { item: result.Item });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'CREATE_ALL');

    if (!event.body) {
      return createErrorResponse(400, 'Request body is required');
    }

    const body = JSON.parse(event.body) as Record<string, unknown>;
    const resourceId = generateId();
    const now = getCurrentTimestamp();

    const item = {
      pk: `RESOURCE#${resourceId}`,
      sk: resourceId,
      ...body,
      id: resourceId,
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
      updatedBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      authContext.userId,
      authContext.userName,
      'CREATE',
      'RESOURCE',
      resourceId,
      'Created new resource',
      'SUCCESS',
      undefined,
      item
    );

    return createSuccessResponse(201, { item });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'UPDATE_ALL');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return createErrorResponse(400, 'Resource ID is required');
    }

    if (!event.body) {
      return createErrorResponse(400, 'Request body is required');
    }

    const body = JSON.parse(event.body) as Record<string, unknown>;
    const now = getCurrentTimestamp();

    const getResult = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `RESOURCE#${resourceId}`,
          sk: resourceId,
        },
      })
    );

    if (!getResult.Item) {
      return createErrorResponse(404, 'Resource not found');
    }

    const updatedItem = {
      ...getResult.Item,
      ...body,
      id: resourceId,
      updatedAt: now,
      updatedBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: updatedItem,
      })
    );

    await createAuditLog(
      authContext.userId,
      authContext.userName,
      'UPDATE',
      'RESOURCE',
      resourceId,
      'Updated resource',
      'SUCCESS',
      getResult.Item,
      updatedItem
    );

    return createSuccessResponse(200, { item: updatedItem });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  authContext: { userId: string; role: Role; userName: string }
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(authContext.role, 'DELETE_ALL');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return createErrorResponse(400, 'Resource ID is required');
    }

    const getResult = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `RESOURCE#${resourceId}`,
          sk: resourceId,
        },
      })
    );

    if (!getResult.Item) {
      return createErrorResponse(404, 'Resource not found');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `RESOURCE#${resourceId}`,
          sk: resourceId,
        },
      })
    );

    await createAuditLog(
      authContext.userId,
      authContext.userName,
      'DELETE',
      'RESOURCE',
      resourceId,
      'Deleted resource',
      'SUCCESS',
      getResult.Item,
      undefined
    );

    return createSuccessResponse(200, { message: 'Resource deleted successfully' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return createErrorResponse(403, message);
    }
    return createErrorResponse(500, message);
  }
}

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  try {
    const authContext = extractAuthContext(event);
    const path = event.path || '';
    const method = event.httpMethod || 'GET';

    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event, authContext);
    }

    if (path.match(/^\/api\/[^/]+\/bulk$/) && method === 'POST') {
      const tableIndex = path.split('/')[2];
      return await handleBulkImport(event, tableIndex, authContext);
    }

    if (path === '/resources' && method === 'POST') {
      return await handleCreateResource(event, authContext);
    }

    if (path.match(/^\/resources\/[^/]+$/) && method === 'GET') {
      return await handleGetResourceById(event, authContext);
    }

    if (path.match(/^\/resources\/[^/]+$/) && method === 'PUT') {
      return await handleUpdateResource(event, authContext);
    }

    if (path.match(/^\/resources\/[^/]+$/) && method === 'DELETE') {
      return await handleDeleteResource(event, authContext);
    }

    return createErrorResponse(404, 'Endpoint not found');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Missing authorization token') || message.includes('Invalid authorization token')) {
      return createErrorResponse(401, message);
    }
    return createErrorResponse(500, message);
  }
};