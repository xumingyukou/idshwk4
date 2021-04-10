@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="all", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="reply404", $apply=set(SumStats::SUM, SumStats::UNIQUE));
    SumStats::create([$name="404_founded",
                      $epoch=10min,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        #print result["all"]$sum;
                        local all = result["all"];
                        local reply404 = result["reply404"];
                        if(reply404$sum > 2 && (reply404$sum / all$sum)> 0.2 && (reply404$unique / reply404$sum) > 0.5)
                           print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, reply404$sum, reply404$unique);
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("all", [$host=c$id$orig_h],[$str=c$http$uri]);
    if (code==404)
        SumStats::observe("reply404", [$host=c$id$orig_h],[$str=c$http$uri]);
    }
