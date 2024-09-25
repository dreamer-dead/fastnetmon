#include "graphite.hpp"


#include "../abstract_subnet_counters.hpp"
#include "../fast_library.hpp"
#include "../fastnetmon_types.hpp"
#include "../fastnetmon_configuration_scheme.hpp"

#include <vector>
#include <string_view>

extern log4cpp::Category& logger;

extern fastnetmon_configuration_t fastnetmon_global_configuration;

// Push host traffic to Graphite
bool push_hosts_traffic_counters_to_graphite() {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;

    // Construst a way to read counters from `subnet_counter_t` 
    // for every traffic direction without runtime dispatch
    const struct {
        const direction_t direction;
        const char* const direction_name;
        uint64_t traffic_counter_element_t::* const packets_ptr;
        uint64_t traffic_counter_element_t::* const bytes_ptr;
        uint64_t subnet_counter_t::* const flows_ptr;
    } processed_directions[2] = {
        {INCOMING, "incoming", &traffic_counter_element_t::in_packets, &traffic_counter_element_t::in_bytes, &subnet_counter_t::in_flows},
        {OUTGOING, "outgoing", &traffic_counter_element_t::out_packets, &traffic_counter_element_t::out_bytes, &subnet_counter_t::out_flows},
    };

    graphite_data_t graphite_data;

    std::vector<std::pair<uint32_t, subnet_counter_t>> speed_elements;
    ipv4_host_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& speed_element : speed_elements) {
        const subnet_counter_t* current_speed_element = &speed_element.second;

        // Skip elements with zero speed
        if (current_speed_element->is_zero()) {
            continue;
        }

        std::string client_ip_as_string = convert_ip_as_uint_to_string(speed_element.first);
        // Replace dots by dashes
        std::replace(client_ip_as_string.begin(), client_ip_as_string.end(), '.', '_');

        // Concatenate prefix parts without too many reallocations.
        std::string graphite_ip_prefix = fastnetmon_global_configuration.graphite_prefix;
        graphite_ip_prefix += ".hosts.";
        graphite_ip_prefix += ip_as_string_with_dash_delimiters;
        graphite_ip_prefix += '.';

        for (auto data_direction : processed_directions) {
            const std::string graphite_current_prefix = graphite_ip_prefix + direction_as_string;

            const auto packets = current_speed_element->total.*data_direction.packets_ptr;
            // We do not store zero data to Graphite
            if (packets != 0) {
                graphite_data[graphite_current_prefix + ".pps"] = packets;
            }

            const auto bytes = current_speed_element->total.*data_direction.bytes_ptr;
            if (bytes != 0) {
                graphite_data[graphite_current_prefix + ".bps"] = bytes * 8;
            }

            const auto flows = *current_speed_element.*data_direction.flows_ptr;
            if (flows != 0) {
                graphite_data[graphite_current_prefix + ".flows"] = flows;
            }
        }
    }

    bool graphite_put_result = store_data_to_graphite(fastnetmon_global_configuration.graphite_port,
                                                      fastnetmon_global_configuration.graphite_host, graphite_data);

    if (!graphite_put_result) {
        logger << log4cpp::Priority::ERROR << "Can't store host load data to Graphite server "
               << fastnetmon_global_configuration.graphite_host << " port: " << fastnetmon_global_configuration.graphite_port;
        return false;
    }

    return true;
}

// Push total counters to graphite
bool push_total_traffic_counters_to_graphite() {
    extern total_speed_counters_t total_counters_ipv4;
    extern uint64_t incoming_total_flows_speed;
    extern uint64_t outgoing_total_flows_speed;

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        uint64_t speed_in_pps = total_counters_ipv4.total_speed_average_counters[packet_direction].total.packets;
        uint64_t speed_in_bps = total_counters_ipv4.total_speed_average_counters[packet_direction].total.bytes;

        graphite_data_t graphite_data;

        std::string direction_as_string = get_direction_name(packet_direction);

        // We have flow information only for incoming and outgoing directions
        if (packet_direction == INCOMING or packet_direction == OUTGOING) {
            uint64_t flow_counter_for_this_direction = 0;

            if (packet_direction == INCOMING) {
                flow_counter_for_this_direction = incoming_total_flows_speed;
            } else {
                flow_counter_for_this_direction = outgoing_total_flows_speed;
            }

            graphite_data[fastnetmon_global_configuration.graphite_prefix + ".total." + direction_as_string + ".flows"] =
                flow_counter_for_this_direction;
        }

        graphite_data[fastnetmon_global_configuration.graphite_prefix + ".total." + direction_as_string + ".pps"] = speed_in_pps;
        graphite_data[fastnetmon_global_configuration.graphite_prefix + ".total." + direction_as_string + ".bps"] =
            speed_in_bps * 8;

        bool graphite_put_result = store_data_to_graphite(fastnetmon_global_configuration.graphite_port,
                                                          fastnetmon_global_configuration.graphite_host, graphite_data);

        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store total load data to Graphite server "
                   << fastnetmon_global_configuration.graphite_host << " port: " << fastnetmon_global_configuration.graphite_port;
            return false;
        }
    }

    return true;
}

// Push per subnet traffic counters to graphite
bool push_network_traffic_counters_to_graphite() {
    extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;

    graphite_data_t graphite_data;

    std::vector<std::pair<subnet_cidr_mask_t, subnet_counter_t>> speed_elements;
    ipv4_network_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& itr : speed_elements) {
        const subnet_counter_t* speed                   = &itr.second;
        std::string subnet_as_string_as_dash_delimiters = convert_ipv4_subnet_to_string(itr.first);

        // Replace dots by dashes
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '.', '_');

        // Replace / by dashes too
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '/', '_');

        std::string current_prefix =
            fastnetmon_global_configuration.graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".";

        graphite_data[current_prefix + "incoming.pps"] = speed->total.in_packets;
        graphite_data[current_prefix + "outgoing.pps"] = speed->total.out_packets;
        graphite_data[current_prefix + "incoming.bps"] = speed->total.in_bytes * 8;
        graphite_data[current_prefix + "outgoing.bps"] = speed->total.out_bytes * 8;
    }


    bool graphite_put_result = store_data_to_graphite(fastnetmon_global_configuration.graphite_port,
                                                      fastnetmon_global_configuration.graphite_host, graphite_data);

    if (!graphite_put_result) {
        logger << log4cpp::Priority::ERROR << "Can't store network load data to Graphite server "
               << fastnetmon_global_configuration.graphite_host << " port: " << fastnetmon_global_configuration.graphite_port;
        return false;
    }

    return true;
}


// This thread pushes speed counters to graphite
void graphite_push_thread() {
    extern struct timeval graphite_thread_execution_time;

    // Sleep less then 1 second to capture speed calculated for very first time by speed calculation logic
    boost::this_thread::sleep(boost::posix_time::milliseconds(700));

    while (true) {
        struct timeval start_calc_time;
        gettimeofday(&start_calc_time, NULL);

        // First of all push total counters to Graphite
        push_total_traffic_counters_to_graphite();

        // Push per subnet counters to graphite
        push_network_traffic_counters_to_graphite();

        // Push per host counters to graphite
        push_hosts_traffic_counters_to_graphite();

        struct timeval end_calc_time;
        gettimeofday(&end_calc_time, NULL);

        timeval_subtract(&graphite_thread_execution_time, &end_calc_time, &start_calc_time);

        logger << log4cpp::Priority::DEBUG << "Graphite data pushed in: " << graphite_thread_execution_time.tv_sec
               << " sec " << graphite_thread_execution_time.tv_usec << " microseconds\n";

        boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.clickhouse_metrics_push_period));
    }
}
