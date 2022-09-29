SLASH_REPLACEMENT = "+"
SUFFIX = ".json"


class image:
    @staticmethod
    def encode(img: str) -> str:
        # allow for tags to have the slash replacement, but image names still get replaced

        if ":" in img:
            fields = img.split(":")
            image_name = ":".join(fields[:-1])
            tag = fields[-1]
            image_name = image_name.replace("/", SLASH_REPLACEMENT)
            return f"{image_name}:{tag}"

        if "@" in img:
            fields = img.split("@")
            image_name = "@".join(fields[:-1])
            digest = fields[-1]
            image_name = image_name.replace("/", SLASH_REPLACEMENT)
            return f"{image_name}@{digest}"

        return img.replace("/", SLASH_REPLACEMENT)

    @staticmethod
    def decode(name: str) -> str:
        # allow for tags to have the slash replacement, but image names still get replaced

        if ":" in name:
            fields = name.split(":")
            image_name = ":".join(fields[:-1])
            tag = fields[-1]
            image_name = image_name.replace(SLASH_REPLACEMENT, "/")
            return f"{image_name}:{tag}"

        if "@" in name:
            fields = name.split("@")
            image_name = "@".join(fields[:-1])
            digest = fields[-1]
            image_name = image_name.replace(SLASH_REPLACEMENT, "/")
            return f"{image_name}@{digest}"

        return name.replace(SLASH_REPLACEMENT, "/")
