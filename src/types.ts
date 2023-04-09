export type $Agent = {
  platform: string;
  os: string;
  browser: string;
  ip: string;
  country?: string;
  city?: string;
};

export type $AccessTokenPayload = {
  id: string;
  tokenType: string;
  tokenId: string;
};
