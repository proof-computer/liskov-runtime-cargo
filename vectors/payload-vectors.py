#!/usr/bin/env python3
"""Offline reproducible Ed25519/descriptor vectors; --check never writes."""
import argparse
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')

def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()

def compact(obj):
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode()

def pretty(obj):
    return (json.dumps(obj, indent=2, ensure_ascii=False) + '\n').encode()

content = b'offline payload fixture\n'
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as archive:
    directory = tarfile.TarInfo('bin')
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    archive.addfile(directory)
    file = tarfile.TarInfo('bin/app')
    file.size = len(content)
    file.mode = 0o755
    archive.addfile(file, io.BytesIO(content))
compressed = io.BytesIO()
with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0, compresslevel=9) as output:
    output.write(buf.getvalue())
archive_bytes = compressed.getvalue()
descriptor = {
    'format': 'liskov.cargo-payload.v1',
    'artifactDigest': digest(archive_bytes),
    'artifactSizeBytes': len(archive_bytes),
    'encryption': 'none',
    'targetAbi': {'os': 'linux', 'architecture': 'aarch64', 'environment': 'musl'},
    'entries': [
        {'kind': 'directory', 'path': 'bin'},
        {'kind': 'regular_file', 'path': 'bin/app', 'sizeBytes': len(content), 'digest': digest(content), 'executable': True},
    ],
    'entrypoints': ['bin/app'],
    'producer': {'kind': 'member', 'subject': 'org-fixture:member-fixture', 'sourceRevision': 'local-fixture-v1', 'buildId': 'build-fixture'},
}
descriptor_invalid = []
def bad_descriptor(name, key, value, reason):
    item = copy.deepcopy(descriptor)
    item[key] = value
    descriptor_invalid.append({'name': name, 'descriptor': item, 'reason': reason})
bad_descriptor('signer-encryption', 'encryption', 'signer', 'unsupported_encryption')
bad_descriptor('unknown-encryption', 'encryption', 'future', 'malformed')
bad_descriptor('invalid-format', 'format', 'tar.gz', 'unsupported_format')
bad_descriptor('invalid-abi', 'targetAbi', {'os': 'linux', 'architecture': '../aarch64', 'environment': 'musl'}, 'invalid_abi')
bad_descriptor('invalid-provenance', 'producer', {'kind': 'member', 'subject': '', 'sourceRevision': 'local', 'buildId': 'build'}, 'invalid_provenance')
bad_descriptor('zero-archive', 'artifactSizeBytes', 0, 'invalid_size')
bad_descriptor('over-configured-limit', 'artifactSizeBytes', 8388609, 'invalid_size')
bad_descriptor('bad-digest', 'artifactDigest', 'sha256:' + 'A' * 64, 'invalid_digest')
for path in ['/bin/app', '../app', 'bin/../app', 'bin//app', 'bin/app/', 'bin\\app', 'bin/%61pp']:
    entry = copy.deepcopy(descriptor['entries'][1]); entry['path'] = path
    bad_descriptor('unsafe-path-' + path, 'entries', [entry], 'invalid_path')
bad_descriptor('duplicate-path', 'entries', [descriptor['entries'][1]] * 2, 'invalid_inventory')
bad_descriptor('too-many-entries', 'entries', [descriptor['entries'][1]] * 257, 'invalid_inventory')
bad_descriptor('escaping-entrypoint', 'entrypoints', ['../app'], 'invalid_entrypoint')
bad_descriptor('directory-entrypoint', 'entrypoints', ['bin'], 'invalid_entrypoint')
entry = copy.deepcopy(descriptor['entries'][1]); entry['executable'] = False
bad_descriptor('not-executable', 'entries', [entry], 'invalid_entrypoint')
entry = copy.deepcopy(descriptor['entries'][1]); entry['sizeBytes'] = 4294967297
bad_descriptor('expansion-limit', 'entries', [entry], 'expansion_limit')
entry = copy.deepcopy(descriptor['entries'][1]); entry['sizeBytes'] = 18446744073709551615
other = copy.deepcopy(entry); other['path'] = 'bin/b'; other['sizeBytes'] = 1
bad_descriptor('expansion-overflow', 'entries', [entry, other], 'overflow')
for kind in ['symlink', 'hardlink', 'device']:
    bad_descriptor(kind, 'entries', [{'kind': kind, 'path': 'bin/app'}], 'malformed')
key = Ed25519PrivateKey.from_private_bytes(SEED)
request = {
    'domain': 'proof.liskov.payload-download.v1',
    'method': 'GET',
    'requestTarget': '/v1/payloads/' + descriptor['artifactDigest'],
    'range': {'mode': 'whole'},
    'artifactDigest': descriptor['artifactDigest'],
    'organisationId': 'org-fixture',
    'applicationUid': 'app-0123456789abcdef0123456789abcdef',
    'job': {'originKind': 'acurast', 'originKey': '0x' + '11' * 32, 'sequence': '340282366920938463463374607431768211455'},
    'processorId': 'processor-fixture',
    'runtimeInstanceId': 'incarnation-fixture',
    'launch': {'launchId': 'launch-fixture', 'policyDigest': 'sha256:' + '22' * 32},
    'workload': None,
    'issuedAtMs': 1700000000000,
    'expiresAtMs': 1700000060000,
    'nonce': '33' * 32,
}
binding = {k: copy.deepcopy(request[k]) for k in ['organisationId', 'applicationUid', 'job', 'processorId', 'runtimeInstanceId', 'artifactDigest', 'launch', 'workload']}
binding['authorizationExpiresAtMs'] = request['expiresAtMs']
valid = []
for name, selection, workload in [
    ('whole-launch', {'mode': 'whole'}, None),
    ('single-range-launch', {'mode': 'bytes', 'start': 0, 'endInclusive': 15}, None),
    ('single-range-workload', {'mode': 'bytes', 'start': 16, 'endInclusive': 31}, {'authorizationId': 'update-fixture', 'revisionDigest': 'sha256:' + '44' * 32, 'policyDigest': 'sha256:' + '55' * 32}),
]:
    item = copy.deepcopy(request); item['range'] = selection; item['workload'] = workload
    item['nonce'] = hashlib.sha256(name.encode()).hexdigest()
    message = compact(item)
    signature = key.sign(message)
    key.public_key().verify(signature, message)
    valid.append({'name': name, 'envelope': {'request': item, 'signature': signature.hex()}, 'messageUtf8': message.decode(), 'messageDigest': digest(message)})
invalid = []
base = valid[0]['envelope']
def bad_request(name, field, value, phase, reason):
    envelope = copy.deepcopy(base); envelope['request'][field] = value
    invalid.append({'name': name, 'envelope': envelope, 'phase': phase, 'reason': reason, 'signatureValid': False})
bad_request('alter-method', 'method', 'POST', 'parse', 'method_mismatch')
bad_request('alter-target', 'requestTarget', request['requestTarget'] + '?x=1', 'parse', 'target_mismatch')
bad_request('alter-range', 'range', {'mode': 'bytes', 'start': 0, 'endInclusive': 15}, 'signature', 'invalid_signature')
bad_request('whole-range-extra-field', 'range', {'mode': 'whole', 'start': 0, 'endInclusive': 15}, 'parse', 'malformed_envelope')
bad_request('inverted-range', 'range', {'mode': 'bytes', 'start': 5, 'endInclusive': 4}, 'parse', 'invalid_range')
bad_request('wrong-app', 'applicationUid', 'app-other', 'binding', 'wrong_application')
bad_request('wrong-org', 'organisationId', 'org-other', 'binding', 'wrong_application')
job = copy.deepcopy(request['job']); job['sequence'] = '0'
bad_request('wrong-job', 'job', job, 'binding', 'wrong_job')
bad_request('wrong-processor', 'processorId', 'processor-other', 'binding', 'wrong_job')
bad_request('wrong-incarnation', 'runtimeInstanceId', 'incarnation-other', 'binding', 'wrong_incarnation')
launch = copy.deepcopy(request['launch']); launch['launchId'] = 'launch-other'
bad_request('wrong-launch', 'launch', launch, 'binding', 'wrong_launch')
bad_request('wrong-workload', 'workload', valid[2]['envelope']['request']['workload'], 'binding', 'wrong_workload')
bad_request('empty-nonce', 'nonce', '', 'parse', 'invalid_nonce')
bad_request('uppercase-nonce', 'nonce', 'AA' * 32, 'parse', 'invalid_nonce')
bad_request('negative-time', 'issuedAtMs', -1, 'parse', 'invalid_time')
bad_request('span-over-60s', 'expiresAtMs', request['expiresAtMs'] + 1, 'parse', 'invalid_time')
bad_request('zero-span', 'expiresAtMs', request['issuedAtMs'], 'parse', 'invalid_time')
bad_request('unsafe-time', 'expiresAtMs', 9007199254740992, 'parse', 'invalid_time')
bad_request('timestamp-overflow', 'issuedAtMs', -9223372036854775808, 'parse', 'overflow')
bad_request('range-overflow', 'range', {'mode': 'bytes', 'start': 0, 'endInclusive': 18446744073709551615}, 'parse', 'overflow')
bad_request('unsafe-range', 'range', {'mode': 'bytes', 'start': 0, 'endInclusive': 9007199254740992}, 'parse', 'invalid_range')
job = copy.deepcopy(request['job']); job['sequence'] = '01'
bad_request('noncanonical-job', 'job', job, 'parse', 'invalid_job_reference')
job['sequence'] = '340282366920938463463374607431768211456'
bad_request('job-overflow', 'job', job, 'parse', 'invalid_job_reference')
artifact = 'sha256:' + '66' * 32
bad_request('wrong-artifact', 'artifactDigest', artifact, 'binding', 'wrong_artifact')
invalid[-1]['envelope']['request']['requestTarget'] = '/v1/payloads/' + artifact
for name, method, target, header, now, reason in [
    ('transport-method', 'HEAD', request['requestTarget'], None, request['issuedAtMs'], 'method_mismatch'),
    ('transport-target', 'GET', request['requestTarget'] + '/', None, request['issuedAtMs'], 'target_mismatch'),
    ('transport-range', 'GET', request['requestTarget'], 'bytes=0-15', request['issuedAtMs'], 'range_mismatch'),
    ('multipart-range', 'GET', request['requestTarget'], 'bytes=0-1,3-4', request['issuedAtMs'], 'invalid_range'),
    ('transport-inverted-range', 'GET', request['requestTarget'], 'bytes=5-4', request['issuedAtMs'], 'invalid_range'),
    ('not-yet-valid', 'GET', request['requestTarget'], None, request['issuedAtMs'] - 1, 'not_yet_valid'),
    ('expired', 'GET', request['requestTarget'], None, request['expiresAtMs'], 'expired'),
]:
    invalid.append({'name': name, 'envelope': copy.deepcopy(base), 'phase': 'transport', 'reason': reason, 'signatureValid': True, 'method': method, 'target': target, 'rangeHeader': header, 'nowMs': now})
outputs = {
    'payload-archive-v1.tar.gz': archive_bytes,
    'payload-descriptor-v1.json': pretty({'descriptor': descriptor, 'canonicalUtf8': compact(descriptor).decode(), 'descriptorDigest': digest(compact(descriptor)), 'archiveDigest': digest(archive_bytes), 'artifactLimitBytes': 8388608, 'invalid': descriptor_invalid}),
    'payload-download-v1.json': pretty({'provenance': 'BKLG-20261013-bw93; Python cryptography Ed25519; RFC8032 test seed; independently checked by Node crypto', 'testOnlySeedHex': SEED.hex(), 'publicKeyHex': key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), 'expectedBinding': binding, 'valid': valid, 'invalid': invalid}),
}
outputs['payload-fixtures.sha256'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in sorted(outputs.items())).encode()
parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true'); args = parser.parse_args()
for name, data in outputs.items():
    path = ROOT / name
    if args.check:
        assert path.read_bytes() == data, f'fixture drift: {name}'
    else:
        path.write_bytes(data)
print(f'payload vectors: {len(valid)} signed requests, {len(invalid)} negative requests, {len(descriptor_invalid)} negative descriptors verified')
