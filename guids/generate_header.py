import argparse
import os
import sys


def generate(input: str, output: str) -> bool:
    out = list()
    with open(input, "r") as f:
        guids = sorted(
            filter(
                lambda guidl: not guidl.endswith("Guid")
                and "ProtocolGuid" not in guidl,
                f.read().splitlines(),
            )
        )

    unique_guids = set()

    out.append("#include <map>")
    out.append("#include <string>\n")
    out.append("static std::map<std::string, std::string> g_module_guids = {")

    for guidl in guids:
        guid, name = guidl.split(",")
        if guid in unique_guids:
            continue
        unique_guids.add(guid)
        out.append(f'    {{"{guid}", "{name}"}},')

    out.append("};\n")

    try:
        with open(output, "w") as f:
            f.write("\n".join(out))
    except Exception as e:
        print(f"Error: {e}")
        return False

    return True


def main() -> bool:
    parser = argparse.ArgumentParser(description="Generate guids.h from guids.csv file")
    parser.add_argument(
        "--input",
        "-i",
        dest="input",
        required=True,
        help="Path to the input csv",
        type=str,
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output",
        required=True,
        help="Path to the output header",
        type=str,
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        sys.exit("Input file path is invalid")

    return generate(args.input, args.output)


if __name__ == "__main__":
    main()
