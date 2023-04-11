// Global Types
import type {
  NextFunction as $Next,
  Request as $Request,
  Response as $Response,
} from 'express';

// Helpers
import _ from 'lodash';
import {
  expressjwt,
} from 'express-jwt';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt-nodejs';
import geoip from 'geoip-lite';
import useragentMiddleware from 'express-useragent';
import {
  getItem,
} from '@vroskus/library-cookies/dist/node';

// Types
import type {
  $AccessTokenPayload,
  $Agent,
} from './types';

export * from './types';

const algorithm: jwt.Algorithm = 'HS256';

// authCheckMiddleware method
export const authCheckMiddleware = <ATP extends $AccessTokenPayload>({
  accessTokenCheck,
  cookie,
  secret,
}: {
  accessTokenCheck: (arg0: ATP) => Promise<boolean>;
  cookie?: string;
  secret: string;
}) => {
  const config = {
    algorithms: [algorithm],
    getToken: undefined,
    isRevoked: async (req: $Request, {
      payload,
    }) => accessTokenCheck(payload),
    requestProperty: 'user',
    secret,
  };

  if (cookie) {
    config.getToken = (req: $Request) => getItem(
      req,
      cookie,
    );
  }

  return expressjwt(config);
};

// authResponseMiddleware method
export const authResponseMiddleware = <REQ extends $Request>(
  params: (arg0: Error, arg1: $Response, arg2: REQ) => unknown,
) => (
    error: Error,
    req: REQ,
    res: $Response,
    next: $Next,
  ) => {
    if (error.name === 'UnauthorizedError') {
      params(
        error,
        res,
        req,
      );
    } else {
      next();
    }
  };

// userIdMiddleware
export const userIdMiddleware = <REQ extends $Request>({
  cookie,
  setUserId,
}: {
  cookie: string,
  setUserId: (userId: string) => void,
}) => (
    req: REQ,
    res: $Response,
    next: $Next,
  ) => {
    try {
      const accessToken: string | void = getItem(
        req,
        cookie,
      );

      if (accessToken) {
        const accessTokenPayload = jwt.decode(accessToken) as $AccessTokenPayload;

        if (accessTokenPayload && accessTokenPayload.id) {
          setUserId(accessTokenPayload.id);
        }
      }
    /* eslint-disable-next-line no-empty */
    } catch (e) {}

    next();
  };

export const agentMiddleware = () => useragentMiddleware.express();

export const generateAccessToken = <AT extends object>(
  params: {
    payload: AT;
    secret: string;
  },
): string => {
  const accessToken = jwt.sign(
    params.payload,
    params.secret,
    {
      algorithm,
    },
  );

  return accessToken;
};

export const generatePassword = (
  input: string,
): string => bcrypt.hashSync(
  input,
  bcrypt.genSaltSync(12),
);

export const validatePassword = (
  input: string,
  hash: string | void,
): boolean => bcrypt.compareSync(
  input,
  hash,
);

export const getRequestAgent = (req: $Request): $Agent => {
  const userAgent: {
    platform: string;
    os: string;
    browser: string;
  } | null = _.get(
    req,
    'useragent',
    null,
  );

  if (userAgent === null) {
    throw new Error('UserAgent middleware is not present');
  }

  const {
    browser,
    os,
    platform,
  } = userAgent;
  const {
    ip,
  } = req;

  const output = {
    browser,
    city: undefined,
    country: undefined,
    ip,
    os,
    platform,
  };

  const geoData: {
    country: string;
    city: string;
  } | null = geoip.lookup(ip);

  if (geoData !== null) {
    output.country = geoData.country;
    output.city = geoData.city;
  }

  return output;
};