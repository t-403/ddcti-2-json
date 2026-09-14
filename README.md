# ddcti-2-json
#### project
- this script parses a selection of [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) markdown tables to convert them to a filtered `data.json` (only "online" entries are kept)
- `data.json` is updated via github actions every 12hrs (only if there are new commits to the selected files)
- selected files: [forum.md](https://github.com/fastfire/deepdarkCTI/blob/main/forum.md), [markets.md](https://github.com/fastfire/deepdarkCTI/blob/main/markets.md), [ransomware_gang.md](https://github.com/fastfire/deepdarkCTI/blob/main/ransomware_gang.md), [telegram_infostealer.md](https://github.com/fastfire/deepdarkCTI/blob/main/telegram_infostealer.md), [telegram_threat_actors.md](https://github.com/fastfire/deepdarkCTI/blob/main/telegram_threat_actors.md), [twitter_threat_actors.md](https://github.com/fastfire/deepdarkCTI/blob/main/twitter_threat_actors.md)

#### useful `jq`
```
jq '[.[] | select(.category == "telegram_threat_actors") | {indicator, description}]' data.json
jq -r '.[] | select(.category == "telegram_threat_actors") | "\(.indicator)\t\t\(.description)"' data.json
```

#### notes 
- kudos to [fastfire](https://github.com/fastfire/) for the upstream sourcing
- script fully vibecoded, see `update.py` docstring 
- beware of legit assets, do not feed directly into WAF
- e.g. `ransomlook.io` in the `ransomware_gang` category
