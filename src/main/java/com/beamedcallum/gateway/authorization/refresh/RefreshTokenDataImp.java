package com.beamedcallum.gateway.authorization.refresh;

import com.beamedcallum.gateway.tokens.Token;

class RefreshTokenDataImp<K  extends Token, V extends Token> implements RefreshTokenData<K, V> {
    private K RefreshToken;
    private V AuthToken;

    public RefreshTokenDataImp(K refreshToken, V authToken) {
        RefreshToken = refreshToken;
        AuthToken = authToken;
    }

    @Override
    public K getRefreshToken() {
        return RefreshToken;
    }

    @Override
    public V getAuthToken() {
        return AuthToken;
    }

    @Override
    public RefreshTokenData<K, V> getNext() {
        return null;
    }
}
