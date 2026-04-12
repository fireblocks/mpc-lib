#include "cosigner/bam_ecdsa_cosigner_client.h"
#include "cosigner/bam_ecdsa_cosigner_server.h"
#include "cosigner/bam_key_persistency_client.h"
#include "cosigner/bam_key_persistency_server.h"
#include "cosigner/bam_tx_persistency_server.h"
#include "cosigner/bam_tx_persistency_client.h"
#include "cosigner/platform_service.h"
#include "cosigner/eddsa_online_signing_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "blockchain/mpc/hd_derive.h"
#include "../src/common/cosigner/utils.h"

#include <chrono>
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <openssl/rand.h>
#include <uuid/uuid.h>
#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37
#endif

namespace fbc = fireblocks::common::cosigner;

static const constexpr uint64_t server_id = 3213454843;
static const constexpr uint64_t client_id = 45234523;
static std::string _tenant_id;

static std::string get_tenant_id()
{
    if (_tenant_id.empty())
    {
        uuid_t uid;
        _tenant_id.resize(UUID_STR_LEN);
        uuid_generate_random(uid);
        uuid_unparse(uid, _tenant_id.data());
    }
    return _tenant_id;
}

// ---- Persistency stubs (same as test) ----

template <class KeyMetadataType, class TempDataType>
class bench_bam_key_persistency
{
public:
    bool key_exist(const std::string& key_id) const { return _keyStore.count(key_id) != 0; }
    void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key)
    {
        _keyStore[key_id].first = algorithm;
        memcpy(_keyStore[key_id].second, private_key, sizeof(elliptic_curve256_scalar_t));
    }
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
    {
        const auto it = _keyStore.find(key_id);
        if (it == _keyStore.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        memcpy(private_key, it->second.second, sizeof(elliptic_curve256_scalar_t));
        algorithm = it->second.first;
    }
    void store_key_metadata(const std::string& key_id, const KeyMetadataType& metadata, const bool overwrite)
    {
        auto it = _metadata_store.find(key_id);
        if (it != _metadata_store.end()) { if (!overwrite) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY); it->second = metadata; }
        else _metadata_store[key_id] = metadata;
    }
    void load_key_metadata(const std::string& key_id, KeyMetadataType& metadata) const
    {
        const auto it = _metadata_store.find(key_id);
        if (it == _metadata_store.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        metadata = it->second;
    }
    void store_temp_data(const std::string& key_id, const TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it != _temp_data.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        if constexpr (std::is_array_v<TempDataType>) memcpy(_temp_data[key_id], data, sizeof(TempDataType));
        else _temp_data[key_id] = data;
    }
    void load_and_delete_temp_data(const std::string& key_id, TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it == _temp_data.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        if constexpr (std::is_array_v<TempDataType>) memcpy(data, it->second, sizeof(TempDataType));
        else data = it->second;
        _temp_data.erase(it);
    }
    void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) { _setup_tenant[setup_id] = tenant_id; }
    void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const
    {
        const auto it = _setup_tenant.find(setup_id);
        if (it == _setup_tenant.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        tenant_id = it->second;
    }
private:
    std::map<std::string, std::pair<cosigner_sign_algorithm, elliptic_curve256_scalar_t>> _keyStore;
    std::map<std::string, KeyMetadataType> _metadata_store;
    std::map<std::string, TempDataType> _temp_data;
    std::map<std::string, std::string> _setup_tenant;
};

class bench_bam_key_persistency_client : public fbc::bam_key_persistency_client, public fbc::bam_tx_persistency_client
{
public:
    virtual ~bench_bam_key_persistency_client() = default;
    void store_tenant_id_for_setup(const std::string& s, const std::string& t) override { _store.store_tenant_id_for_setup(s, t); }
    void load_tenant_id_for_setup(const std::string& s, std::string& t) const override { _store.load_tenant_id_for_setup(s, t); }
    void store_key(const std::string& k, cosigner_sign_algorithm a, const elliptic_curve256_scalar_t& p) override { _store.store_key(k, a, p); }
    void load_key(const std::string& k, cosigner_sign_algorithm& a, elliptic_curve256_scalar_t& p) const override { _store.load_key(k, a, p); }
    void store_key_metadata(const std::string& k, const fbc::bam_key_metadata_client& m, bool o) override { _store.store_key_metadata(k, m, o); }
    void load_key_metadata(const std::string& k, fbc::bam_key_metadata_client& m) const override { _store.load_key_metadata(k, m); }
    void store_key_temp_data(const std::string& k, const fbc::bam_temp_key_data_client& d) override { _store.store_temp_data(k, d); }
    void load_key_temp_data_and_delete(const std::string& k, fbc::bam_temp_key_data_client& d) override { _store.load_and_delete_temp_data(k, d); }
    void store_signature_data(const std::string& tx_id, const fbc::bam_client_signature_data& d) override { _sig_data["txid_" + tx_id] = d; }
    void load_signature_data_and_delete(const std::string& tx_id, fbc::bam_client_signature_data& d) override
    {
        auto it = _sig_data.find("txid_" + tx_id);
        if (it == _sig_data.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        d = it->second; _sig_data.erase(it);
    }
    bool delete_temporary_tx_data(const std::string&) override { return true; }
    bool delete_temporary_key_data(const std::string&) override { return true; }
    bool delete_key_data(const std::string&) override { return true; }
    bool delete_setup_data(const std::string&) override { return true; }
    bool backup_key(const std::string&) const override { return true; }
private:
    bench_bam_key_persistency<fbc::bam_key_metadata_client, fbc::bam_temp_key_data_client> _store;
    std::map<std::string, fbc::bam_client_signature_data> _sig_data;
};

class bench_bam_key_persistency_server : public fbc::bam_key_persistency_server, public fbc::bam_tx_persistency_server
{
public:
    virtual ~bench_bam_key_persistency_server() = default;
    void store_tenant_id_for_setup(const std::string& s, const std::string& t) override { _store.store_tenant_id_for_setup(s, t); }
    void load_tenant_id_for_setup(const std::string& s, std::string& t) const override { _store.load_tenant_id_for_setup(s, t); }
    void store_key(const std::string& k, cosigner_sign_algorithm a, const elliptic_curve256_scalar_t& p) override { _store.store_key(k, a, p); }
    void load_key(const std::string& k, cosigner_sign_algorithm& a, elliptic_curve256_scalar_t& p) const override { _store.load_key(k, a, p); }
    void store_key_metadata(const std::string& k, const fbc::bam_key_metadata_server& m, bool o) override { _store.store_key_metadata(k, m, o); }
    void load_key_metadata(const std::string& k, fbc::bam_key_metadata_server& m) const override { _store.load_key_metadata(k, m); }
    void store_signature_data(const std::string& tx_id, const std::shared_ptr<fbc::bam_server_signature_data>& d) override { _store.store_temp_data("txid_" + tx_id, *d); }
    std::shared_ptr<fbc::bam_server_signature_data> load_signature_data_and_delete(const std::string& tx_id) override
    {
        auto p = std::make_shared<fbc::bam_server_signature_data>();
        _store.load_and_delete_temp_data("txid_" + tx_id, *p);
        return p;
    }
    bool delete_temporary_tx_data(const std::string&) override { return true; }
    bool delete_temporary_key_data(const std::string&) override { return true; }
    bool delete_key_data(const std::string&) override { return true; }
    bool delete_setup_data(const std::string&) override { return true; }
    void store_setup_auxilary_key(const std::string& s, const fbc::bam_setup_auxilary_key_server& d) override { _setup_aux[s] = d; }
    void load_setup_auxilary_key(const std::string& s, fbc::bam_setup_auxilary_key_server& d) const override
    {
        auto it = _setup_aux.find(s);
        if (it == _setup_aux.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        d = it->second;
    }
    void store_setup_metadata(const std::string& s, const fbc::bam_setup_metadata_server& d) override { _setup_meta[s] = d; }
    void load_setup_metadata(const std::string& s, fbc::bam_setup_metadata_server& d) const override
    {
        auto it = _setup_meta.find(s);
        if (it == _setup_meta.end()) throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        d = it->second;
    }
    bool backup_key(const std::string&) const override { return true; }
private:
    bench_bam_key_persistency<fbc::bam_key_metadata_server, fbc::bam_server_signature_data> _store;
    std::map<std::string, fbc::bam_setup_auxilary_key_server> _setup_aux;
    std::map<std::string, fbc::bam_setup_metadata_server> _setup_meta;
};

class bench_platform_service : public fbc::platform_service
{
public:
    ~bench_platform_service() = default;
    void gen_random(size_t len, uint8_t* random_data) const override { RAND_bytes(random_data, len); }
    bool backup_key(const std::string&, cosigner_sign_algorithm, const elliptic_curve256_scalar_t&, const fbc::cmp_key_metadata&, const fbc::auxiliary_keys&) override { return true; }
    void derive_initial_share(const fbc::share_derivation_args&, cosigner_sign_algorithm, elliptic_curve256_scalar_t*) const override { assert(0); }
    void on_start_signing(const std::string&, const std::string&, const fbc::signing_data&, const std::string&, const std::set<std::string>&, const signing_type) override {}
    bool is_client_id(uint64_t) const override { return false; }
    const std::string get_current_tenantid() const override { return get_tenant_id(); }
    uint64_t get_id_from_keyid(const std::string&) const override { return 0; }
    void fill_signing_info_from_metadata(const std::string&, std::vector<uint32_t>&) const override {}
    void fill_eddsa_signing_info_from_metadata(std::vector<fbc::eddsa_signature_data>&, const std::string&) const override {}
    void fill_bam_signing_info_from_metadata(std::vector<fbc::bam_signing_properties>&, const std::string&) const override {}
    fbc::byte_vector_t encrypt_for_player(const uint64_t, const fbc::byte_vector_t& data, const std::optional<std::string>&) const override { return data; }
    fbc::byte_vector_t decrypt_message(const fbc::byte_vector_t& data) const override { return data; }
    void prepare_for_signing(const std::string&, const std::string) override {}
    void mark_key_setup_in_progress(const std::string&) const override {}
    void clear_key_setup_in_progress(const std::string&) const override {}
};

// ---- Benchmark logic ----

struct BenchSetup
{
    bench_bam_key_persistency_client persistencyClient;
    bench_bam_key_persistency_server persistencyServer;
    bench_platform_service platform;
    fbc::bam_ecdsa_cosigner_server server{platform, persistencyServer, persistencyServer};
    fbc::bam_ecdsa_cosigner_client client{platform, persistencyClient, persistencyClient};
};

void bam_keygen(const std::string& setup_id, const std::string& key_id,
                BenchSetup& s, cosigner_sign_algorithm alg)
{
    fbc::bam_ecdsa_cosigner::client_key_shared_data cm;
    fbc::bam_ecdsa_cosigner::server_key_shared_data sm;
    fbc::bam_ecdsa_cosigner::generated_public_key gpk;
    commitments_sha256_t B;
    fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;

    s.server.generate_setup_with_proof(setup_id, get_tenant_id(), alg, setup);
    s.client.start_new_key_generation(setup_id, key_id, get_tenant_id(), server_id, client_id, alg);
    s.server.generate_share_and_commit(setup_id, key_id, server_id, client_id, alg, B);
    s.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, key_id, server_id, setup, B, cm);
    s.server.verify_client_proofs_and_decommit_share_with_proof(key_id, client_id, cm, sm);
    s.client.verify_key_decommitment_and_proofs(key_id, server_id, client_id, sm, gpk);
}

double bam_sign_once(const std::string& setup_id, const std::string& key_id,
                     BenchSetup& s, cosigner_sign_algorithm alg)
{
    uuid_t uid;
    char txid[UUID_STR_LEN] = {'\0'};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);

    elliptic_curve256_scalar_t hash;
    RAND_bytes(hash, sizeof(hash));

    fbc::signing_data data = {{0}, {{fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), {44, 0, 0, 0, 0}}}};

    std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
    std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
    std::vector<fbc::recoverable_signature> full_signatures;
    cosigner_sign_algorithm signature_algorithm;

    auto start = std::chrono::high_resolution_clock::now();

    s.client.prepare_for_signature(key_id, txid, 0, server_id, client_id, data, "", std::set<std::string>());
    s.server.generate_signature_share(key_id, txid, 0, server_id, client_id, alg, data, "", std::set<std::string>(), server_shares);
    s.client.compute_partial_signature(txid, server_shares, partial_signatures);
    s.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm);

    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void run_benchmark(const char* name, cosigner_sign_algorithm alg, int warmup, int iterations)
{
    BenchSetup s;
    uuid_t uid;
    char keyid[UUID_STR_LEN] = {'\0'};
    uuid_generate_random(uid);
    uuid_unparse(uid, keyid);
    std::string setup_id(keyid);

    std::cout << "=== " << name << " ===" << std::endl;
    std::cout << "  Key generation..." << std::flush;
    bam_keygen(setup_id, keyid, s, alg);
    std::cout << " done" << std::endl;

    // Warmup
    std::cout << "  Warmup (" << warmup << " iterations)..." << std::flush;
    for (int i = 0; i < warmup; i++)
    {
        bam_sign_once(setup_id, keyid, s, alg);
    }
    std::cout << " done" << std::endl;

    // Measured runs
    double total_ms = 0;
    double min_ms = 1e9, max_ms = 0;
    std::cout << "  Benchmarking (" << iterations << " iterations)..." << std::flush;
    for (int i = 0; i < iterations; i++)
    {
        double ms = bam_sign_once(setup_id, keyid, s, alg);
        total_ms += ms;
        if (ms < min_ms) min_ms = ms;
        if (ms > max_ms) max_ms = ms;
    }
    std::cout << " done" << std::endl;

    double avg_ms = total_ms / iterations;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Results:" << std::endl;
    std::cout << "    Iterations: " << iterations << std::endl;
    std::cout << "    Avg:        " << avg_ms << " ms" << std::endl;
    std::cout << "    Min:        " << min_ms << " ms" << std::endl;
    std::cout << "    Max:        " << max_ms << " ms" << std::endl;
    std::cout << "    Total:      " << total_ms << " ms" << std::endl;
    std::cout << "    Throughput: " << std::setprecision(1) << (1000.0 / avg_ms) << " sign/sec" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char** argv)
{
    int warmup = 2;
    int iterations = 20;

    if (argc > 1) iterations = atoi(argv[1]);
    if (argc > 2) warmup = atoi(argv[2]);

    std::cout << "BAM ECDSA Signing Benchmark" << std::endl;
    std::cout << "==========================" << std::endl << std::endl;

    run_benchmark("secp256k1", ECDSA_SECP256K1, warmup, iterations);
    run_benchmark("secp256r1", ECDSA_SECP256R1, warmup, iterations);

    return 0;
}
