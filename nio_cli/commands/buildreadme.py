import json, os, re
from collections import defaultdict
from .base import Base


class BuildReadme(Base):

    def run(self):
        if os.path.exists('README.md'):
            with open('README.md') as f:
                lines = [l.rstrip() for l in f.readlines()]
            old_readme = self._read_readme(lines)
        else:
            old_readme = {}
        with open('spec.json') as f:
            spec = json.load(f)
        new_readme = self._write_readme(old_readme, spec)
        with open("{}".format('README.md'), 'w') as f:
            [f.write("{}\n".format(line)) for line in new_readme]

    def _read_readme(self, lines):
        old_readme = defaultdict(lambda: defaultdict(list))
        prev = None
        BLOCK_SEP = r'\*+$'
        current_block = ""
        current_section = "Description"
        for line in lines:
            is_new_block = line.startswith("==")
            is_new_section = line.startswith("--")
            is_block_seperator = re.match(BLOCK_SEP, line)
            if is_new_block:
                current_block = prev
                current_section = "Description"
                prev = None
            elif is_new_section:
                current_section = prev
                prev = None
            elif is_block_seperator:
                prev = None
            else:
                if prev is not None:
                    old_readme[current_block][current_section].append(prev)
                prev = line
        # Save the final line of the file
        if prev is not None:
            old_readme[current_block][current_section].append(prev)
        return old_readme

    def _write_readme(self, old_readme, spec):
        writelines = []
        required_sections = \
            ["description", "properties", "inputs", "outputs", "commands"]
        for block in sorted(spec):
            block_name = block.split("/")[1]
            writelines.append(block_name)
            writelines.append(len(block_name) * "=")
            for section in required_sections:
                if section != "description":
                    writelines.append(section.title())
                    writelines.append(len(section) * "-")
                if section in ["properties", "commands", "inputs", "outputs"]:
                    for property in sorted(spec[block][section]):
                        description = spec[block][section][property].get(
                            "description", "None")
                        writelines.append(
                            "- **{}**: {}".format(property, description))
                else:
                    writelines.append(spec[block][section])
                writelines.append("")
            for section in sorted(old_readme.get(block_name, {})):
                if section.lower() not in required_sections:
                    writelines.append(section)
                    writelines.append(len(section) * "-")
                    [writelines.append(line)
                    for line in old_readme[block_name][section] if line]
                    writelines.append("")
        return writelines
