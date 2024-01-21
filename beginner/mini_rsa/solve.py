from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

leak = 24986288511406610689718446624210347240800254679541887917496550238025724025245366296475758347972917098615315083893786596239213463034880126152583583770452304
c = 5926440800047066468184992240057621921188346083131741617482777221394411358243130401052973132050605103035491365016082149869814064434831123043357292949645845605278066636109516907741970960547141266810284132826982396956610111589
n = 155735289132981544011017189391760271645447983310532929187034314934077442930131653227631280820261488048477635481834924391697025189196282777696908403230429985112108890167443195955327245288626689006734302524489187183667470192109923398146045404320502820234742450852031718895027266342435688387321102862096023537079

e = 3

m = iroot(c, 3)[0]
m = long_to_bytes(m)
print(m)

# flag{S0_y0u_c4n_s0lv3_s0m3_RSA}
