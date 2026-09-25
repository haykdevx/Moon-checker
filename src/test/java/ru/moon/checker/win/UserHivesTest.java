package ru.moon.checker.win;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class UserHivesTest {

    /** Records mount traffic; refuses a second mount of a file that is already mounted. */
    static final class FakeMounter implements UserHives.Mounter {
        final List<String> mounts = new ArrayList<>();
        final List<String> unmounts = new ArrayList<>();
        final List<Path> busy = new ArrayList<>();

        public synchronized List<UserHives.User> loadedUsers() {
            return List.of(new UserHives.User(Registry.HKU, "S-1-5-21-1\\", "player"));
        }

        public synchronized List<Path> offlineProfiles(List<UserHives.User> loaded) {
            return List.of(Path.of("Users", "alt"));
        }

        public synchronized boolean mount(String key, Path ntuserDat) {
            if (busy.contains(ntuserDat)) {
                return false; // like reg.exe: the hive file is in use
            }
            busy.add(ntuserDat);
            mounts.add(key);
            return true;
        }

        public synchronized void unmount(String key) {
            unmounts.add(key);
            busy.clear();
        }
    }

    private final UserHives.Mounter original = UserHives.mounter;

    @AfterEach
    void restore() {
        UserHives.mounter = original;
    }

    @Test
    void parallelScopesShareOneMountAndUnmountAfterTheLastClose() throws Exception {
        FakeMounter fake = new FakeMounter();
        UserHives.mounter = fake;

        UserHives.Scope a = UserHives.open();
        UserHives.Scope b = UserHives.open();
        // both modules see the logged-off "alt" user, not just the one that mounted first
        assertEquals(2, a.users().size());
        assertEquals(2, b.users().size());
        assertEquals("alt", b.users().get(1).label());
        assertEquals(1, fake.mounts.size());

        a.close();
        a.close(); // idempotent: must not release b's reference
        assertTrue(fake.unmounts.isEmpty(), "still in use by scope b");
        b.close();
        assertEquals(List.of("MoonChk_1"), fake.unmounts);
    }

    @Test
    void concurrentOpenersNeverDoubleMount() throws Exception {
        FakeMounter fake = new FakeMounter();
        UserHives.mounter = fake;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<java.util.concurrent.Future<Integer>> seen = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            seen.add(pool.submit(() -> {
                go.await();
                try (UserHives.Scope s = UserHives.open()) {
                    return s.users().size();
                }
            }));
        }
        go.countDown();
        for (var f : seen) {
            assertEquals(2, f.get(5, TimeUnit.SECONDS));
        }
        pool.shutdownNow();
        assertEquals(fake.mounts.size(), fake.unmounts.size(), "every mount is released");
    }
}
