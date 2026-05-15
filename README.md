# dmarc-analyzer
Small **local-only** tool: upload DMARC **aggregate** reports (ZIP with `.xml` / `.xml.gz`, or raw XML), see high-signal rows (disposition not `none`, DKIM+SPF double fail, optional DKIM-only / SPF-alignment noise).
