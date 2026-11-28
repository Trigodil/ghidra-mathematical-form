"""Resolve an application entry and recover packaged files without executing them."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

MAX_FILES = 100000
MAX_BYTES = 4 * 1024**3
MAX_HEADER = 16 * 1024**2


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def application_root(entry):
    entry = entry.resolve(strict=True)
    if not entry.is_file():
        return entry
    # Only expand a file into a directory when a packaged application identifies it.
    for parent in (entry.parent, entry.parent.parent):
        if (parent / 'resources/app.asar').is_file():
            return parent
    return entry


def source_key(source, root, output):
    if root.is_file():
        return source.name
    if source.is_relative_to(root):
        return source.relative_to(root).as_posix()
    return '@archives/' + source.relative_to(output / 'application').as_posix()


def component(part):
    if (not isinstance(part, str) or not part or part in ('.', '..')
            or any(c in part for c in ('/', '\\', '\0'))):
        raise ValueError('Unsafe archive path component')
    return part


def regular(path, boundary):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Not a regular file: {path}')
    if not path.resolve().is_relative_to(boundary.resolve()):
        raise ValueError(f'File escapes its application: {path}')
    cursor = path.parent
    while cursor != boundary:
        if cursor.is_symlink() or cursor == cursor.parent:
            raise ValueError(f'Linked parent directory: {path}')
        cursor = cursor.parent
    if boundary.is_symlink():
        raise ValueError(f'Linked input root: {boundary}')


class Recovery:
    def __init__(self, output):
        self.output = output / 'application'
        self.output.mkdir(parents=True, exist_ok=True)
        self.files = []
        self.archives = []
        self.issues = []
        self.iterations = []
        self.bytes = 0

    def copy(self, stream, size, destination, source, integrity=None):
        if (type(size) is not int or size < 0 or len(self.files) >= MAX_FILES
                or self.bytes + size > MAX_BYTES):
            raise ValueError('Application extraction budget exceeded')
        if not destination.is_relative_to(self.output):
            raise ValueError('Output escapes application directory')
        cursor = destination
        while cursor != self.output.parent:
            if cursor.is_symlink():
                raise ValueError('Linked output path')
            cursor = cursor.parent
        destination.parent.mkdir(parents=True, exist_ok=True)
        hash_ = hashlib.sha256()
        remaining = size
        fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix='.recover-')
        try:
            with os.fdopen(fd, 'wb') as target:
                while remaining:
                    data = stream.read(min(remaining, 1024**2))
                    if not data:
                        raise ValueError('Truncated application file')
                    hash_.update(data)
                    target.write(data)
                    remaining -= len(data)
            sha = hash_.hexdigest()
            if integrity is not None:
                if (not isinstance(integrity, dict) or integrity.get('algorithm') != 'SHA256'
                        or integrity.get('hash') != sha):
                    raise ValueError('ASAR member integrity mismatch')
            os.replace(temporary, destination)
            self.bytes += size
            row = dict(source=str(source), output=str(destination), bytes=size, sha256=sha)
            self.files.append(row)
            return row
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def extract(self, archive, destination):
        archive_sha = digest(archive)
        with archive.open('rb') as stream:
            prefix = stream.read(16)
            if len(prefix) != 16:
                raise ValueError('Truncated ASAR header')
            first, header, payload, length = struct.unpack('<IIII', prefix)
            if (first != 4 or not 8 <= header <= MAX_HEADER or payload != header - 4
                    or length > header - 8 or 8 + header > archive.stat().st_size):
                raise ValueError('Invalid ASAR header extents')
            index = json.loads(stream.read(length))
            pending = [(Path(), index, 0)]
            count = 0
            while pending:
                relative, node, depth = pending.pop()
                count += 1
                if count > MAX_FILES or depth > 64 or not isinstance(node, dict):
                    raise ValueError('ASAR directory budget or schema invalid')
                if 'files' in node:
                    if not isinstance(node['files'], dict):
                        raise ValueError('Invalid ASAR directory')
                    if count + len(pending) + len(node['files']) > MAX_FILES:
                        raise ValueError('ASAR directory entry budget exceeded')
                    for name, child in sorted(node['files'].items(), reverse=True):
                        pending.append((relative / component(name), child, depth + 1))
                    continue
                if 'link' in node:
                    self.issues.append(dict(path=f'{archive}!/{relative}', reason='archive symlink not followed'))
                    continue
                size = node.get('size')
                if type(size) is not int or size < 0:
                    raise ValueError('Invalid ASAR member size')
                if node.get('unpacked'):
                    boundary = archive.with_name(archive.name + '.unpacked')
                    source = boundary / relative
                    regular(source, boundary)
                    if source.stat().st_size != size:
                        raise ValueError('ASAR unpacked member size mismatch')
                    with source.open('rb') as external:
                        self.copy(external, size, destination / relative, f'{archive}!/{relative}', node.get('integrity'))
                else:
                    offset = node.get('offset')
                    if not isinstance(offset, str) or not offset.isdecimal():
                        raise ValueError('Invalid ASAR member offset')
                    start = 8 + header + int(offset)
                    if start + size > archive.stat().st_size:
                        raise ValueError('ASAR member outside input')
                    stream.seek(start)
                    self.copy(stream, size, destination / relative, f'{archive}!/{relative}', node.get('integrity'))
        if digest(archive) != archive_sha:
            raise ValueError('Archive changed during recovery')
        return dict(path=str(archive), sha256=archive_sha, output=str(destination), status='extracted')

    def recover(self, root, native_paths):
        known_native = {digest(p): p for p in native_paths}
        native, aliases, queue = [], [], []
        if root.is_file():
            return native, self.report(aliases)
        for folder, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [d for d in sorted(dirs) if not (Path(folder) / d).is_symlink()
                       and not (Path(folder) / d).resolve().is_relative_to(self.output.parent)]
            for name in sorted(names):
                source = Path(folder) / name
                if source.is_symlink():
                    continue
                try:
                    regular(source, root)
                    with source.open('rb') as stream:
                        if stream.read(4) == b'\x7fELF':
                            continue
                        stream.seek(0)
                        self.copy(stream, source.stat().st_size, self.output / 'resources' / source.relative_to(root), source)
                    if source.suffix == '.asar':
                        queue.append((source, 0))
                except (OSError, ValueError) as error:
                    self.issues.append(dict(path=str(source), reason=str(error)))
        seen = set()
        while queue:
            next_queue = []
            round_ = dict(round=len(self.iterations) + 1, archives=0, new_native_files=0)
            for archive, depth in queue:
                try:
                    if depth > 8:
                        raise ValueError('Nested archive depth exceeded')
                    key = (digest(archive), str(archive))
                    if key in seen:
                        continue
                    seen.add(key)
                    destination = self.output / 'archives' / hashlib.sha256(str(archive).encode()).hexdigest()[:16]
                    before = len(self.files)
                    self.archives.append(self.extract(archive, destination))
                    round_['archives'] += 1
                    for row in self.files[before:]:
                        member = Path(row['output'])
                        if member.suffix == '.asar':
                            next_queue.append((member, depth + 1))
                        with member.open('rb') as stream:
                            magic = stream.read(4)
                        if magic == b'\x7fELF':
                            if row['sha256'] in known_native:
                                aliases.append(dict(path=str(member), analyzed_as=str(known_native[row['sha256']])))
                            else:
                                known_native[row['sha256']] = member
                                native.append(member)
                                round_['new_native_files'] += 1
                        elif magic[:2] == b'MZ':
                            self.issues.append(dict(path=str(member), reason='unsupported PE member'))
                except (OSError, ValueError, TypeError, RecursionError) as error:
                    self.issues.append(dict(path=str(archive), reason=str(error)))
            self.iterations.append(round_)
            queue = next_queue
        return native, self.report(aliases)

    def report(self, aliases):
        return dict(status='partial' if self.issues else 'files_recovered', files=self.files,
                    archives=self.archives, issues=self.issues, native_aliases=aliases,
                    iterations=self.iterations, fixpoint_reached=not self.issues,
                    stop_reason='blocked' if self.issues else 'no_new_components', target_executed=False,
                    whole_application_recovered=False)
