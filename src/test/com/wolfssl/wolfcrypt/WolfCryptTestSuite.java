package com.wolfssl.wolfcrypt;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ AesTest.class, Des3Test.class, Md5Test.class, ShaTest.class,
		Sha256Test.class, Sha384Test.class, Sha512Test.class, HmacTest.class,
		RngTest.class, RsaTest.class, DhTest.class, EccTest.class })
public class WolfCryptTestSuite {

}
