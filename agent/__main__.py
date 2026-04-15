from __future__ import annotations

import argparse
import asyncio

from agent.scan_runtime import (
    build_auth_args,
    prepare_output_path,
    resolve_target_name,
    run_scan,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP Security DAST Agent")

    parser.add_argument("--target", required=True)

    parser.add_argument(
        "--target-name",
        required=False,
        help="Logical target name, e.g. dvwa, webgoat, juice_shop",
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        help="Base output directory, e.g. /out",
    )

    parser.add_argument(
        "--seed-url",
        action="append",
        default=[],
        help="Additional seed URL(s). Can be provided multiple times.",
    )

    parser.add_argument(
        "--auth-username",
        help="Username for optional pre-authentication",
    )

    parser.add_argument(
        "--auth-password",
        help="Password for optional pre-authentication",
    )

    args = parser.parse_args()

    auth = build_auth_args(args)
    target_name = resolve_target_name(args.target, args.target_name)
    out_path = prepare_output_path(args.out_dir, target_name)

    raise SystemExit(
        asyncio.run(
            run_scan(
                args.target,
                out_path,
                seed_urls=args.seed_url,
                auth=auth,
            )
        )
    )


if __name__ == "__main__":
    main()
