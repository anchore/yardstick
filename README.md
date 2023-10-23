# yardstick

A tool that can parse and compare the results of vulnerability scanner tools.

Manage and explore scan results:
```
# capture a new scan result for a specific tool and image
yardstick result capture --image ubuntu:20.04 -t grype@v0.11.0

# list all scan results that have been captured
yardstick result list

# explore the scan results interactively
yardstick result explore <UUID>
```

Manage true positive / false positive labels for images:
```
# explore labels applied to specific scan-result matches for an image and tool pair
yardstick label explore <UUID>

# list all managed labels
yardstick label list
```

Supported scanners:
- `grype`
- `syft`

### F.A.Q.

*"Why is syft on this list? It's not a vulnerability scanner!"*

Right you are, however, capturing SBOM results that can be fed into grype or for
reference during analysis is quite useful!


*"Yardstick doesn't support vulnerability scanner X..."*

PR's are welcome! The goal of this tool is to provide the analysis capabilities
to understand how we can make these scanners better.



## Result Sets

Result sets can be useful to operate on and track results from scans taken at the same time. For instance:
```yaml
# .yardstick.yaml
result-sets:
  example:
    matrix:
      images:
        - ubuntu:20.04
      tools:
        - name: grype
          version: v0.32.0
        - name: grype
          version: v0.48.0
```

```bash
# capture results for all tools
$ yardstick result capture -r example

# see the specific result details
$ yardstick result list -r example

# perform a label comparison using all tooling
$ yardstick label compare -r example
```


## Configuration

Sample application config:
```yaml
# .yardstick.yaml

x-ref:
  images: &images
    - docker.io/cloudbees/cloudbees-core-mm:2.346.4.1@sha256:b8ec61aad2f5f9be2dc9c68923eab1de0e8b026176093ad2e0742fca310bf3bf

result-sets:
  pr-vs-latest:
    description: "latest released grype vs grype from the current build"
    matrix:
      images: *images
      tools:
        - name: syft                      # go ahead and capture an SBOM each time to help analysis later
          version: v0.54.0
          produces: SBOM

        - name: grype                     # from the latest published github release
          version: latest
          takes: SBOM

        - name: grype:pr                  # from a local PR checkout install (feed via an environment variable)
          version: env:CURRENT_GRYPE_COMMIT
          takes: SBOM
```

## CLI Commands

```
  config  show the application config

  label   manage match labels

    add                   add a match label indication for an image
    apply                 see which labels apply to the given image and...
    compare               compare a scan result against labeled data
    compare-by-ecosystem  show TPs/FPs/Precision from label comparison...
    explore               interact with an label results for a single image...
    images                show all images derived from label data
    list                  show all labels
    remove                remove a match label indication for an image
    set-image-parent      set the parent image for a given image
    show-image-lineage    show all parents and children for the given image

  result  manage image scan results

    capture  capture all tool output for the given image
    clear    remove all results and result sets
    compare  show a comparison between tool output
    explore  interact with an image scan result
    images   list images in results
    import   import results for a tool that were run externally
    list     list stored results
    sets     list configured result sets
    show     show a the results for a single scan + tool
    tools    list tools in results
```
