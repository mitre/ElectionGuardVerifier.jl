using Test
using ElectionGuardVerifier.Loader
using ElectionGuardVerifier.ElGamal

@testset "ElGamal Cryptosystem" begin

    c = load_constants()

    k = make_keys(c)

    encr_one = encr(c, true, k.pubk)

    @test decr(k, encr_one)

    encr_zero = encr(c, false, k.pubk)

    @test !decr(k, encr_zero)

end
