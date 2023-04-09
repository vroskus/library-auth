// Global Types
import type {
  Request as $Request,
  Response as $Response,
} from 'express';

// Helpers
import express from 'express';
import bodyParser from 'body-parser';
import request from 'supertest';

import {
  authCheckMiddleware,
  authResponseMiddleware,
  generateAccessToken,
  generatePassword,
  userIdMiddleware,
  validatePassword,
} from '../src';

// Types
import type {
  $AccessTokenPayload,
} from '../src';

const secret = 'secret';

describe(
  'auth',
  () => {
    let app;

    const accessTokenCheck = async (
      accessTokenPayload: $AccessTokenPayload,
    ): Promise<boolean> => accessTokenPayload.tokenId !== 'string';

    const setUserId = (userId: string) => {
      if (userId === 'string') {
        throw new Error('Invalid user id');
      }
    };

    beforeAll(() => {
      app = express();
      app.use(bodyParser.json());
      app.use(authCheckMiddleware({
        accessTokenCheck,
        secret,
      }));
      app.use(authResponseMiddleware((error, res) => res.status(401).json({
        error: true,
      })));
      app.use(userIdMiddleware({
        cookie: 'Authorization',
        setUserId,
      }));
      app.get(
        '/',
        (req: $Request, res: $Response) => res.json({
          done: true,
        }),
      );
    });

    describe(
      'middleware',
      () => {
        it(
          'should reject unauthorized access',
          async () => {
            const response = await request(app).get('/');

            expect(response.status).toBe(401);
            expect(response.body).toHaveProperty(
              'error',
              true,
            );
          },
        );

        it(
          'should allow authorized access',
          async () => {
            const accessToken = generateAccessToken({
              payload: {
                id: 'string',
                tokenId: 'string',
                tokenType: 'string',
              },
              secret,
            });
            const response = await request(app).get('/').set(
              'Authorization',
              `Bearer ${accessToken}`,
            );

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty(
              'done',
              true,
            );
          },
        );

        it(
          'should validate access token expirity',
          async () => {
            const accessToken = generateAccessToken({
              payload: {
                exp: Math.floor(Date.now() / 1000) + 1,
                id: 'string',
                tokenId: 'string',
                tokenType: 'string',
              },
              secret,
            });

            const response1 = await request(app).get('/').set(
              'Authorization',
              `Bearer ${accessToken}`,
            );

            expect(response1.status).toBe(200);
            expect(response1.body).toHaveProperty(
              'done',
              true,
            );

            await new Promise((r) => {
              setTimeout(
                r,
                1000,
              );
            });

            const response2 = await request(app).get('/').set(
              'Authorization',
              `Bearer ${accessToken}`,
            );

            expect(response2.status).toBe(401);
            expect(response2.body).toHaveProperty(
              'error',
              true,
            );
          },
        );

        it(
          'should validate access token revokation',
          async () => {
            const accessToken = generateAccessToken({
              payload: {
                id: 'string',
                tokenId: 'string1',
                tokenType: 'string',
              },
              secret,
            });
            const response = await request(app).get('/').set(
              'Authorization',
              `Bearer ${accessToken}`,
            );

            expect(response.status).toBe(401);
            expect(response.body).toHaveProperty(
              'error',
              true,
            );
          },
        );
      },
    );

    describe(
      'password',
      () => {
        it(
          'should generate password',
          async () => {
            const password = 'password';
            const passwordHash = generatePassword(password);

            expect(passwordHash).not.toBe(password);
          },
        );

        it(
          'should validate password',
          async () => {
            const password = 'password';
            const passwordHash = generatePassword(password);
            const result = validatePassword(
              password,
              passwordHash,
            );

            expect(result).toBe(true);
          },
        );
      },
    );
  },
);
