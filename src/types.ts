export type $Agent = {
  browser: string;
  city?: string;
  country?: string;
  ip: string;
  os: string;
  platform: string;
};

export type $AccessTokenPayload = {
  id: string;
  tokenId: string;
  tokenType: string;
};
