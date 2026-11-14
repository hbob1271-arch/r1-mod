"""Read-only inventory verification. Reports never imply gameplay completion.

Python 3.10+. No external dependencies. Input: {"files": {relative_path:
{"size": integer, "sha256": hex}}}. Report output must be a new file outside
all input trees. Exit 0: all three trees match; 1: incomplete; 2: invalid input.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys

STAGES = ("decoded_or_parsed", "identified", "integrated", "dependencies_verified",
          "game_loaded", "functionally_tested", "complete")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path):
    raw = Path(path).read_bytes()
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict) or not data["files"]:
        raise ValueError("manifest requires a nonempty files object")
    validate_files(data["files"])
    return data["files"], hashlib.sha256(raw).hexdigest()


def validate_files(files):
    seen = set()
    for name, entry in files.items():
        parts = name.split("/")
        if (not name or "\\" in name or PureWindowsPath(name).drive
                or any(p in ("", ".", "..") or p.endswith((".", " "))
                       or re.search(r'[<>:"|?*\x00-\x1f]', p)
                       or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', p)
                       for p in parts)):
            raise ValueError(f"unsafe relative path: {name!r}")
        if name.casefold() in seen:
            raise ValueError(f"case-insensitive path collision: {name}")
        seen.add(name.casefold())
        if (not isinstance(entry, dict) or type(entry.get("size")) is not int
                or entry["size"] < 0 or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"])):
            raise ValueError(f"invalid size/SHA256 for {name}")
    # A file cannot simultaneously be another file's parent directory.
    for name in files:
        parts = name.casefold().split("/")
        if any("/".join(parts[:i]) in seen for i in range(1, len(parts))):
            raise ValueError(f"file/directory collision: {name}")


def verify_file(root, name, expected):
    if root is None:
        return {"status": "unavailable", "reason": "tree not supplied"}
    path = root
    try:
        for part in name.split("/"):
            path = path / part
            if path.is_symlink():
                return {"status": "unsafe", "reason": "symlink component"}
        if not stat.S_ISREG(path.stat().st_mode):
            return {"status": "unsafe", "reason": "not a regular file"}
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                return {"status": "unsafe", "reason": "not a regular file"}
            digest = hashlib.sha256()
            while block := stream.read(1024 * 1024):
                digest.update(block)
            after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(path.stat()):
            return {"status": "changed_during_read"}
        actual = digest.hexdigest()
        return {"status": "match" if after.st_size == expected["size"] and
                actual == expected["sha256"].lower() else "mismatch",
                "size": after.st_size, "sha256": actual}
    except FileNotFoundError:
        return {"status": "missing"}
    except OSError as error:
        return {"status": "unreadable", "reason": type(error).__name__}


def reconcile(files, roots, manifest_hash):
    entries = []
    for name, expected in sorted(files.items()):
        checks = {label: verify_file(root, name, expected) for label, root in roots.items()}
        entries.append({"path": name,
                        "expected": {"size": expected["size"], "sha256": expected["sha256"].lower()},
                        "file_checks": checks,
                        "stages": {s: {"status": "unknown", "evidence": []} for s in STAGES}})
    extras, scan_errors = {}, {}
    for label, root in roots.items():
        extras[label], scan_errors[label] = [], []
        if root is None:
            continue
        def onerror(error):
            scan_errors[label].append(type(error).__name__)
        for folder, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
            links = [d for d in dirs if (Path(folder) / d).is_symlink()]
            dirs[:] = [d for d in dirs if d not in links]
            for name in names + links:
                relative = (Path(folder) / name).relative_to(root).as_posix()
                if relative not in files:
                    extras[label].append(relative)
        extras[label].sort()
    summary = {label: {status: sum(e["file_checks"][label]["status"] == status for e in entries)
                      for status in sorted({e["file_checks"][label]["status"] for e in entries})}
               for label in roots}
    integrity = all(c["status"] == "match" for e in entries for c in e["file_checks"].values())
    return {"generatedBy": "CodeRabbit", "schemaVersion": 1,
            "manifestSha256": manifest_hash, "entryCount": len(entries),
            "summary": summary, "unlistedPaths": extras, "scanErrors": scan_errors,
            "allExpectedFilesMatch": integrity and not any(scan_errors.values()),
            "gameCompletion": "unverified", "entries": entries}



def load_content_inventory(path):
    """Read the existing documentary v461 map/mode export, not a guessed asset graph."""
    raw = Path(path).read_bytes()
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or data.get("targetVersion") != "3.19.26.22 / fastfile v461":
        raise ValueError("content inventory must identify 3.19.26.22 / fastfile v461")
    for field in ("maps", "specialModes", "standardModes"):
        if not isinstance(data.get(field), list):
            raise ValueError(f"content inventory requires {field} list")
    if not data["maps"]:
        raise ValueError("content inventory maps cannot be empty")
    for field, packages in (("maps", "recordedPackages"), ("specialModes", "recordedAddons")):
        seen = set()
        for item in data[field]:
            if not isinstance(item, dict):
                raise ValueError(f"invalid {field} record")
            name = item.get("internalId")
            if (not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name)
                    or name in seen):
                raise ValueError(f"invalid or duplicate {field} internalId")
            seen.add(name)
            records = item.get(packages)
            if not isinstance(records, list) or (field == "maps" and not records):
                raise ValueError(f"invalid {packages} for {name}")
            paths = set()
            for record in records:
                if not isinstance(record, dict) or not isinstance(record.get("relativePath"), str):
                    raise ValueError(f"invalid package record for {name}")
                path = record["relativePath"]
                # Reuse the file manifest's safety/identity contract, without opening the path.
                validate_files({path: record})
                if path.casefold() in paths:
                    raise ValueError(f"duplicate package for {name}: {path}")
                paths.add(path.casefold())
                dependencies = record.get("dependencies")
                if dependencies is not None:
                    if not isinstance(dependencies, list) or not all(isinstance(d, str) for d in dependencies):
                        raise ValueError(f"invalid dependencies for {path}")
                    if len({d.casefold() for d in dependencies}) != len(dependencies):
                        raise ValueError(f"duplicate dependencies for {path}")
                    validate_files({d: {"size": 0, "sha256": "0" * 64} for d in dependencies})
                if field == "specialModes" and not isinstance(record.get("mapId"), str):
                    raise ValueError(f"addon requires mapId: {path}")
    extraction = data.get("extraction", {})
    if not isinstance(extraction, dict):
        raise ValueError("invalid extraction counts")
    actual_counts = {"baseMapIds": len(data["maps"]),
                     "matchedIfsFiles": sum(len(m["recordedPackages"]) for m in data["maps"])}
    for field, count in actual_counts.items():
        if field in extraction and (type(extraction[field]) is not int or extraction[field] != count):
            raise ValueError(f"content inventory {field} count disagrees with records")
    slots = set()
    for mode in data["standardModes"]:
        if (not isinstance(mode, dict) or not isinstance(mode.get("slot"), str)
                or not mode["slot"] or mode["slot"] in slots
                or any(mode.get(field) is not None and not isinstance(mode[field], str)
                       for field in ("confirmedDisplayName", "internalId"))):
            raise ValueError("invalid or duplicate standard mode slot")
        slots.add(mode["slot"])
    return data, hashlib.sha256(raw).hexdigest()


def content_coverage(report, inventory, inventory_hash):
    """Join only declared references to already checked files. Never infer runtime dependencies."""
    files = {entry["path"]: entry for entry in report["entries"]}
    map_ids = {item["internalId"] for item in inventory["maps"]}
    issues = []

    def group(item, field):
        packages = []
        for reference in item[field]:
            path = reference["relativePath"]
            entry = files.get(path)
            status = "consistent"
            if entry is None:
                status = "absent_from_manifest"
            elif (reference["size"] != entry["expected"]["size"] or
                  reference["sha256"].lower() != entry["expected"]["sha256"]):
                status = "metadata_conflict"
            if field == "recordedAddons" and reference["mapId"] not in map_ids:
                issues.append({"owner": item["internalId"], "path": path,
                               "status": "unknown_map_reference", "mapId": reference["mapId"]})
            if status != "consistent":
                issues.append({"owner": item["internalId"], "path": path, "status": status})
            package = {"path": path, "referenceStatus": status,
                       "fileChecks": entry["file_checks"] if entry else {}}
            if field == "recordedAddons":
                package["mapId"] = reference["mapId"]
            packages.append(package)
        coverage = {}
        for tree in report["summary"]:
            statuses = [p["fileChecks"].get(tree, {}).get("status", "unavailable") for p in packages]
            # An empty reference set is unknown, never a successful verification.
            coverage[tree] = {"packageCount": len(packages),
                              "matchingPackages": statuses.count("match"),
                              "recordedPackagesMatch": bool(packages) and all(s == "match" for s in statuses)
                                  and all(p["referenceStatus"] == "consistent" for p in packages)}
        return {"internalId": item["internalId"], "packages": packages, "coverage": coverage,
                "dependencyGraph": "unavailable", "runtimeStatus": "unverified"}

    maps = [group(item, "recordedPackages") for item in inventory["maps"]]
    modes = [group(item, "recordedAddons") for item in inventory["specialModes"]]
    for mode in modes:
        mode["mapEligibility"] = "unverified"
    return {"inventorySha256": inventory_hash, "targetVersion": inventory["targetVersion"],
            "scope": "declared outer packages only; not decoded asset dependencies or mode eligibility",
            "referencesConsistent": not issues, "issues": issues, "maps": maps,
            "specialModes": modes, "standardModes": [{field: m.get(field) for field in ("slot", "confirmedDisplayName", "internalId")}
                              for m in inventory["standardModes"]],
            "gameCompletion": "unverified"}


def content_validation(report, inventory):
    """Deterministic container dependency projection, with no game-functionality promotion."""
    files = {e["path"]: e for e in report["entries"]}
    maps = {m["internalId"]: m for m in inventory["maps"]}
    declarations, conflicts = {}, set()
    for item in inventory["maps"] + inventory["specialModes"]:
        for p in item.get("recordedPackages", item.get("recordedAddons", [])):
            path, deps = p["relativePath"], p.get("dependencies")
            if deps is not None:
                deps = sorted(deps)
                if path in declarations and declarations[path] != deps:
                    conflicts.add(path)
                declarations[path] = min(declarations.get(path, deps), deps)

    def file_status(path, tree):
        if path not in files:
            return {"status": "unlisted", "reason": "dependency not in baseline"}
        entry = files[path]
        check = entry["file_checks"].get(tree, {"status": "unavailable"})
        status = check["status"]
        if status == "match":
            status = "verified"
        elif status == "mismatch":
            # Hash corruption means different bytes, not a diagnosis of archive syntax.
            status = "mismatched" if check.get("size") != entry["expected"]["size"] else "corrupt"
        return {**check, "status": status}

    def row(kind, identity, packages, extra_unknown=()):
        refs = {p["relativePath"]: p for p in packages}
        unresolved = list(extra_unknown)
        # Iterative DFS handles cycles and long graphs without Python recursion limits.
        visited, active, edges, cycles = set(), set(), [], set()
        for root in sorted(refs):
            stack = [(root, False)]
            while stack:
                path, leaving = stack.pop()
                if leaving:
                    active.discard(path)
                    continue
                if path in active:
                    cycles.add(path)
                    continue
                if path in visited:
                    continue
                visited.add(path)
                active.add(path)
                stack.append((path, True))
                if path not in declarations:
                    unresolved.append({"path": path, "reason": "dependency_export_unavailable"})
                else:
                    for dep in reversed(declarations[path]):
                        edges.append({"from": path, "to": dep})
                        stack.append((dep, False))
                if path in conflicts:
                    unresolved.append({"path": path, "reason": "conflicting_dependency_declarations"})
        for path in sorted(cycles):
            unresolved.append({"path": path, "reason": "dependency_cycle"})
        for path in sorted(visited):
            if path not in files:
                unresolved.append({"path": path, "reason": "unlisted_dependency"})
            if path in refs and path in files:
                ref, expected = refs[path], files[path]["expected"]
                if ref["size"] != expected["size"] or ref["sha256"].lower() != expected["sha256"]:
                    unresolved.append({"path": path, "reason": "metadata_conflict"})
        if not packages:
            unresolved.append({"path": None, "reason": "package_mapping_unavailable"})
        checks = {tree: [{"path": path, **file_status(path, tree)} for path in sorted(visited)]
                  for tree in sorted(report["summary"])}
        verified = {tree: bool(packages) and not unresolved and all(p["status"] == "verified" for p in rows)
                    for tree, rows in checks.items()}
        return {"kind": kind, "id": identity, "rootPackages": sorted(refs),
                "dependencyEdges": sorted(edges, key=lambda e: (e["from"], e["to"])),
                "unresolvedDependencies": sorted(unresolved, key=lambda e: (e["path"] or "", e["reason"])),
                "fileValidation": checks, "declaredDependenciesVerified": verified,
                "mapModeEligibility": "unverified", "runtimeStatus": "unverified"}

    rows = [row("map", m["internalId"], m["recordedPackages"]) for m in inventory["maps"]]
    for mode in inventory["specialModes"]:
        packages = list(mode["recordedAddons"])
        unknown = []
        # Existing addon mapId is a recorded association; include its base segments,
        # without claiming this is the complete decoded dependency graph.
        for map_id in sorted({p["mapId"] for p in packages}):
            if map_id in maps:
                packages.extend(maps[map_id]["recordedPackages"])
            else:
                unknown.append({"path": map_id, "reason": "unknown_map_reference"})
        rows.append(row("special_mode", mode["internalId"], packages, unknown))
    for mode in inventory["standardModes"]:
        result = row("standard_mode", mode["slot"], [])
        result.update({"internalId": mode.get("internalId"),
                       "confirmedDisplayName": mode.get("confirmedDisplayName")})
        rows.append(result)
    return {"schemaVersion": 1, "scope": "recorded container associations and explicit dependencies only",
            "statusDefinitions": {"verified": "size and SHA256 match baseline; not parsed/game tested",
                                  "mismatched": "size differs from baseline",
                                  "corrupt": "same size but SHA256 differs; format corruption not diagnosed",
                                  "missing": "path absent in supplied tree", "unavailable": "tree not supplied",
                                  "unlisted": "reference absent from baseline"},
            "unlistedFiles": report["unlistedPaths"],
            "records": sorted(rows, key=lambda r: (r["kind"], r["id"])),
            "gameCompletion": "unverified"}


def write_tsv(report, stream):
    """Flatten every baseline row; preserve unknown functional stages explicitly."""
    trees = ("original", "archive", "restoration")
    columns = ["generated_by", "manifest_sha256", "path", "expected_size", "expected_sha256"]
    for tree in trees:
        columns.extend(f"{tree}_{field}" for field in ("status", "size", "sha256", "reason"))
    columns.extend(STAGES)
    columns.append("game_completion")
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for entry in report["entries"]:
        row = {"generated_by": "CodeRabbit", "manifest_sha256": report["manifestSha256"],
               "path": entry["path"], "expected_size": entry["expected"]["size"],
               "expected_sha256": entry["expected"]["sha256"],
               "game_completion": report["gameCompletion"]}
        for tree in trees:
            check = entry["file_checks"].get(tree, {"status": "unavailable", "reason": "tree not supplied"})
            for field in ("status", "size", "sha256", "reason"):
                row[f"{tree}_{field}"] = check.get(field, "")
        for stage in STAGES:
            row[stage] = entry["stages"][stage]["status"]
        writer.writerow(row)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--content-inventory", type=Path,
                        help="existing v461 map/mode JSON export; adds declared package coverage (JSON only)")
    parser.add_argument("--original", type=Path)
    parser.add_argument("--archive-tree", type=Path, help="existing lawful archive member tree; no extraction performed")
    parser.add_argument("--restoration", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "tsv"), default="json",
                        help="TSV exports all baseline rows; JSON also includes unlisted paths and scan errors")
    args = parser.parse_args(argv)
    try:
        files, digest = load_manifest(args.manifest)
        content = None
        if args.content_inventory is not None:
            if args.format != "json":
                raise ValueError("content inventory coverage requires JSON output")
            content = load_content_inventory(args.content_inventory)
        roots = {}
        for label, value in (("original", args.original), ("archive", args.archive_tree),
                             ("restoration", args.restoration)):
            if value is not None and (value.is_symlink() or not value.is_dir()):
                raise ValueError(f"{label}: expected an existing directory, not a symlink")
            roots[label] = value.resolve() if value is not None else None
        output = args.output.resolve()
        if any(root and (output == root or root in output.parents) for root in roots.values()):
            raise ValueError("output must be outside all inspected trees")
        if args.content_inventory is not None and output == args.content_inventory.resolve():
            raise ValueError("output cannot replace content inventory")
        if output == args.manifest.resolve():
            raise ValueError("output cannot replace manifest")
        report = reconcile(files, roots, digest)
        if content is not None:
            report["contentCoverage"] = content_coverage(report, *content)
            report["contentValidation"] = content_validation(report, content[0])
            report["allExpectedFilesMatch"] &= report["contentCoverage"]["referencesConsistent"]
        # Exclusive creation protects existing reports/backups and output symlinks.
        with args.output.open("x", encoding="utf-8", newline="") as stream:
            if args.format == "tsv":
                write_tsv(report, stream)
            else:
                json.dump(report, stream, indent=2)
                stream.write("\n")
        print(json.dumps({"entries": report["entryCount"], "summary": report["summary"],
                          "allExpectedFilesMatch": report["allExpectedFilesMatch"],
                          "unlistedPathCount": sum(map(len, report["unlistedPaths"].values())),
                          "scanErrorCount": sum(map(len, report["scanErrors"].values()))}))
        return 0 if report["allExpectedFilesMatch"] else 1
    except (ValueError, OSError) as error:
        print(f"reconcile: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
