# All filters with a flow of 1M
python3 parse_output.py -c "filters-all" ../in/*L30,T*_1M* ../in/*L30_1M*
#python3 parse_output.py -c "filters-all" ../in/*L30,T*_10\ flows*1M* ../in/*L30_10\ flows*1M* 
#python3 parse_output.py -c "filters-all" ../in/*L30,T*_10\ flows*10M* ../in/*L30_10\ flows*10M* 
python3 parse_output.py -c "filters-all" ../in/*L30,T*_100\ flows* ../in/*L30_100\ flows*
#python3 parse_output.py -c "filters-all" ../in/*L30,T*_1G* ../in/*L30_1G*
# ...
# Comparing baseline and all performances with a filter 
#python3 parse_output.py -c "filters-all_1Mvs128M" ../in/*L30_1M* ../in/*L30_1G* ../in/*T10,T20*

# All alerts with a flow of 1M
python3 parse_output.py -c "alerts-all" ../in/*L30,A*_1M* ../in/*L30_1M*
python3 parse_output.py -c "alerts-all" ../in/*L30,A*_10\ flows*1M* ../in/*L30_10\ flows*1M* 
python3 parse_output.py -c "alerts-all" ../in/*L30,A*_10\ flows*10M* ../in/*L30_10\ flows*10M* 
python3 parse_output.py -c "alerts-all" ../in/*L30,A*_100\ flows* ../in/*L30_100\ flows*
#python3 parse_output.py -c "alerts-all" ../in/*L30,A*_1G* ../in/*L30_1G*