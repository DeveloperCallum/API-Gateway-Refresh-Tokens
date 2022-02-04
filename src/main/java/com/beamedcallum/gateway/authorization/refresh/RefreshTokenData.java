package com.beamedcallum.gateway.authorization.refresh;

import com.beamedcallum.gateway.tokens.Token;

public interface RefreshTokenData<K extends Token, V extends Token> {
    public K getRefreshToken();
    public V getAuthToken();
    public RefreshTokenData<K, V> getNext();
}
