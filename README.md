# ddcti-2-json
#### project
- this script parses a selection of [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) markdown tables and converts them to a filtered `data.json` with only "online" entries kept
- `data.json` is updated via github actions every 12hrs if there are new commits to the selected files
- selected files: [forum.md](https://github.com/fastfire/deepdarkCTI/blob/main/forum.md), [markets.md](https://github.com/fastfire/deepdarkCTI/blob/main/markets.md), [ransomware_gang.md](https://github.com/fastfire/deepdarkCTI/blob/main/ransomware_gang.md), [telegram_infostealer.md](https://github.com/fastfire/deepdarkCTI/blob/main/telegram_infostealer.md), [telegram_threat_actors.md](https://github.com/fastfire/deepdarkCTI/blob/main/telegram_threat_actors.md), [twitter_threat_actors.md](https://github.com/fastfire/deepdarkCTI/blob/main/twitter_threat_actors.md)

#### useful `jq`
```
jq '[.[] | select(.category == "telegram_threat_actors") | {indicator, description}]' data.json
jq -r '.[] | select(.category == "telegram_threat_actors") | "\(.indicator)\t\t\(.description)"' data.json
```

#### notes 
- kudos to [fastfire](https://github.com/fastfire/) for the upstream sourcing
- script fully vibecoded, see `update.py` for the docstring 
- beware of legit assets e.g. `ransomlook.io` in the `ransomware_gang` category
