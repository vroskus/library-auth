// Global Types
import type {
  NextFunction as $Next,
  Request as $Request,
  Response as $Response,
} from 'express';
import type {
  IsRevoked,
  Params,
} from 'express-jwt';
import type {
  Jwt,
} from 'jsonwebtoken';

// Helpers
import _ from 'lodash';
import {
  expressjwt,
} from 'express-jwt';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import geoip from 'geoip-lite';
import useragentMiddleware from 'express-useragent';
import {
  getItem,
  removeItem,
  setItem,
} from '@vroskus/library-cookies/dist/node';

// Types
import type {
  $AccessTokenPayload,
  $Agent,
} from './types';

export * from './types';

const algorithm: jwt.Algorithm = 'HS256';
const salt: number = 12;

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
  let getToken: ((req: $Request) => string | undefined) | undefined;

  const isRevoked: IsRevoked = async (
    req,
    params?: Jwt,
  ) => {
    if (typeof params !== 'undefined' && typeof params.payload !== 'string') {
      const jwtPayload = params.payload as ATP;

      return accessTokenCheck(jwtPayload);
    }

    return true;
  };

  const config: Params = {
    algorithms: [algorithm],
    getToken,
    isRevoked,
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
  cookie: string;
  setUserId: (userId: string) => void;
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
    } catch (e) {
      console.error(e);
    }

    next();
  };

// agentMiddleware
export const agentMiddleware = () => useragentMiddleware.express();

// generateAccessToken
export const generateAccessToken = <AT extends object>(
  params: {
    payload: AT;
    secret: string;
  },
): string => jwt.sign(
    params.payload,
    params.secret,
    {
      algorithm,
    },
  );

// generatePassword
export const generatePassword = (
  input: string,
): string => bcrypt.hashSync(
  input,
  bcrypt.genSaltSync(salt),
);

// validatePassword
export const validatePassword = (
  input: string,
  hash: string | void,
): boolean => {
  if (hash) {
    return bcrypt.compareSync(
      input,
      hash,
    );
  }

  return false;
};

// getRequestAgent
export const getRequestAgent = (req: $Request): $Agent => {
  const userAgent: null | {
    browser: string;
    os: string;
    platform: string;
  } = _.get(
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

  let city: string | undefined;
  let country: string | undefined;

  const output = {
    browser,
    city,
    country,
    ip,
    os,
    platform,
  };

  const geoData: null | {
    city: string;
    country: string;
  } = geoip.lookup(ip);

  if (geoData !== null) {
    output.country = geoData.country;
    output.city = geoData.city;
  }

  return output;
};

// setAuthCookies
export const setAuthCookies = ({
  accessToken,
  domain,
  expires,
  key,
  req,
  secure,
}: {
  accessToken: string;
  domain: string;
  expires: Date;
  key: string;
  req: $Request;
  secure: boolean;
}): void => {
  setItem(
    req,
    key,
    accessToken,
    {
      domain,
      expires,
      secure,
    },
  );
  setItem(
    req,
    key,
    accessToken,
    {
      domain: `.${domain}`,
      expires,
      secure,
    },
  );

  // Only for development environment
  if (!secure) {
    setItem(
      req,
      key,
      accessToken,
      {
        expires,
        secure,
      },
    );
  }
};

// removeAuthCookies
export const removeAuthCookies = ({
  domain,
  key,
  req,
}: {
  domain: string;
  key: string;
  req: $Request;
}): void => {
  removeItem(
    req,
    key,
    {
      domain,
    },
  );
  removeItem(
    req,
    key,
    {
      domain: `.${domain}`,
    },
  );
};
